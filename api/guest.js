/**
 * api/guest.js — Vercel serverless function
 *
 * GET /api/guest?token=<uuid>
 *
 * Validates the guest_token, fetches the member's trip + settlement data,
 * and returns it as JSON. The guest webpage calls this on load.
 *
 * ── Phase-4 correctness fix ─────────────────────────────────────────────────
 * computeBalance previously summed EVERY split — settled ones included — so a
 * guest who had already paid their friend back still showed as owing. The
 * balance now mirrors the app's settlement engine exactly:
 *   - Only unsettled splits create pending debt.
 *   - A split where the member IS the payer (self-share) never creates debt.
 *   - Debt is pairwise; reciprocal debts between the same two people are
 *     netted into one figure. Nothing else is merged.
 *   - "You paid" / "Your share" remain gross totals across the whole trip
 *     (informational stats, deliberately unchanged in meaning).
 * Response stays backward compatible and adds `iSettled` (paise this member
 * has already settled) so the page can reassure "you've paid ₹X already".
 *
 * Security (unchanged, plus two hardening headers):
 *  - SUPABASE_SERVICE_ROLE_KEY is a Vercel environment secret — never
 *    exposed to the browser.
 *  - guest_token is a UUID v4 (2^122 entropy). Not guessable. Strict regex
 *    validation before any DB round-trip.
 *  - Returns ONLY the requesting member's own balance data.
 *  - Rate limited: 30 requests per IP per minute (in-memory sliding window).
 *  - CORS locked to the production domain. No wildcard.
 *  - Cache-Control: no-store — private balance data must never be cached by
 *    intermediaries; X-Robots-Tag: noindex keeps token URLs out of indexes.
 *
 * Runtime: Node.js 20.x (Vercel default)
 * No npm dependencies — uses the built-in fetch (Node 18+).
 */

"use strict";

const ALLOWED_ORIGIN = "https://settravo.sapphirepegasus.com";

const UUID_V4_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * In-memory sliding-window rate limiter.
 * Each Vercel serverless instance has its own map — this is best-effort
 * protection against naive abuse. For production-grade limiting, use
 * Vercel's Edge Middleware with KV, or Upstash Rate Limit.
 *
 * @type {Map<string, number[]>}
 */
const ipTimestamps = new Map();

/**
 * Returns true if this IP has exceeded the rate limit.
 * @param {string} ip
 * @returns {boolean}
 */
function isRateLimited(ip) {
    const now = Date.now();
    const WINDOW_MS = 60_000;
    const MAX_REQUESTS = 30;

    const hits = (ipTimestamps.get(ip) ?? []).filter(
        (t) => now - t < WINDOW_MS
    );

    if (hits.length >= MAX_REQUESTS) return true;

    hits.push(now);
    ipTimestamps.set(ip, hits);
    return false;
}

/**
 * Thin Supabase REST client — no npm package needed.
 * Uses the PostgREST HTTP API directly with the service role key.
 *
 * @param {string} supabaseUrl
 * @param {string} serviceRoleKey
 */
function makeSupabaseClient(supabaseUrl, serviceRoleKey) {
    const base = `${supabaseUrl}/rest/v1`;
    const headers = {
        apikey: serviceRoleKey,
        Authorization: `Bearer ${serviceRoleKey}`,
        "Content-Type": "application/json",
        Accept: "application/json",
    };

    /**
     * @param {string} table
     * @param {Record<string, string>} params  PostgREST query params
     * @returns {Promise<any[]>}
     */
    async function select(table, params) {
        const url = new URL(`${base}/${table}`);
        for (const [k, v] of Object.entries(params)) {
            url.searchParams.set(k, v);
        }

        const res = await fetch(url.toString(), { headers, method: "GET" });

        if (!res.ok) {
            const body = await res.text().catch(() => "(no body)");
            throw new Error(`Supabase error on ${table}: ${res.status} ${body}`);
        }

        return res.json();
    }

    return { select };
}

/**
 * Compute this member's balance using the SAME pairwise, settled-aware rules
 * as the app's settlement engine (src/utils/settlement.ts):
 *
 *  - Pending debt = unsettled splits only, self-shares excluded, netted
 *    per pair of members.
 *  - iPaid / iOwe = gross informational totals over the whole trip.
 *  - iSettled = this member's shares already marked settled (paise).
 *  - myNet = sum of pairwise nets (positive: others owe me).
 *
 * All arithmetic is integer paise — no floating point.
 *
 * Exported for the test suite (scripts/guest-balance.spec.mjs).
 *
 * @param {string} myMemberId
 * @param {{ id: string, paid_by_member: string, amount_money: number }[]} expenses
 * @param {{ expense_id: string, member_id: string, share_money: number, is_settled: boolean }[]} splits
 * @param {Map<string, string>} memberNameMap  memberId → displayName
 */
export function computeBalance(myMemberId, expenses, splits, memberNameMap) {
    /** @type {Map<string, string>} expenseId → payer memberId */
    const payerByExpense = new Map(
        expenses.map((e) => [e.id, e.paid_by_member])
    );

    let iPaid = 0;
    let iOwe = 0;
    let iSettled = 0;

    for (const expense of expenses) {
        if (expense.paid_by_member === myMemberId) {
            iPaid += expense.amount_money;
        }
    }

    /**
     * Pairwise pending ledger involving me:
     * net amount per other member — positive: they owe me.
     * @type {Map<string, number>}
     */
    const netWithMember = new Map();

    for (const split of splits) {
        const payer = payerByExpense.get(split.expense_id);
        if (!payer) continue; // orphaned split — skip defensively

        if (split.member_id === myMemberId) {
            iOwe += split.share_money;
            if (split.is_settled) iSettled += split.share_money;
        }

        // Pending pairwise debt: unsettled, non-self, involving me.
        if (split.is_settled) continue;
        if (split.member_id === payer) continue;
        if (split.share_money <= 0) continue;

        if (split.member_id === myMemberId) {
            // I owe the payer.
            netWithMember.set(payer, (netWithMember.get(payer) ?? 0) - split.share_money);
        } else if (payer === myMemberId) {
            // The split member owes me.
            netWithMember.set(
                split.member_id,
                (netWithMember.get(split.member_id) ?? 0) + split.share_money
            );
        }
    }

    /** @type {{ toName: string; amount: number }[]} */
    const iOweDetails = [];
    /** @type {{ fromName: string; amount: number }[]} */
    const owedToMeDetails = [];
    let myNet = 0;

    for (const [otherId, net] of netWithMember.entries()) {
        if (net === 0) continue;
        myNet += net;
        const otherName = memberNameMap.get(otherId) ?? "A trip member";
        if (net < 0) {
            iOweDetails.push({ toName: otherName, amount: -net });
        } else {
            owedToMeDetails.push({ fromName: otherName, amount: net });
        }
    }

    // Deterministic order: largest amounts first (stable UI).
    iOweDetails.sort((a, b) => b.amount - a.amount);
    owedToMeDetails.sort((a, b) => b.amount - a.amount);

    return { iPaid, iOwe, iSettled, myNet, iOweDetails, owedToMeDetails };
}

/**
 * Main handler — Vercel serverless function signature.
 *
 * @param {import("http").IncomingMessage} req
 * @param {import("http").ServerResponse} res
 */
export default async function handler(req, res) {
    const origin = req.headers["origin"] ?? "";

    res.setHeader("Vary", "Origin");
    // Private financial data: never cache anywhere, never index token URLs.
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Robots-Tag", "noindex, nofollow");

    if (req.method === "OPTIONS") {
        if (origin === ALLOWED_ORIGIN) {
            res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
            res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
            res.setHeader("Access-Control-Allow-Headers", "Content-Type");
            res.setHeader("Access-Control-Max-Age", "86400");
        }
        return res.status(204).end();
    }

    if (req.method !== "GET") {
        return res.status(405).json({ error: "Method not allowed" });
    }

    if (origin && origin !== ALLOWED_ORIGIN) {
        return res.status(403).json({ error: "Forbidden" });
    }

    if (origin === ALLOWED_ORIGIN) {
        res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
    }

    const ip =
        (Array.isArray(req.headers["x-forwarded-for"])
            ? req.headers["x-forwarded-for"][0]
            : req.headers["x-forwarded-for"]) ??
        req.socket?.remoteAddress ??
        "unknown";

    if (isRateLimited(ip)) {
        return res.status(429).json({ error: "Too many requests" });
    }

    const rawUrl = req.url ?? "";
    const urlObj = new URL(rawUrl, `https://${req.headers.host}`);
    const token = urlObj.searchParams.get("token") ?? "";

    if (!UUID_V4_RE.test(token)) {
        return res.status(400).json({ error: "Invalid token" });
    }

    const supabaseUrl = process.env.SUPABASE_URL;
    const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!supabaseUrl || !serviceRoleKey) {
        console.error("[guest] Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
        return res.status(500).json({ error: "Server misconfiguration" });
    }

    const db = makeSupabaseClient(supabaseUrl, serviceRoleKey);

    try {
        const members = await db.select("TravelAppMembers", {
            select: "id,display_name,trip_id,guest_token,device_id",
            guest_token: `eq.${token}`,
            device_id: "is.null",
            limit: "1",
        });

        if (!members.length) {
            return res.status(404).json({ error: "Invalid or expired link" });
        }

        const member = members[0];
        const tripId = member.trip_id;

        const [trips, allMembers, expenses] = await Promise.all([
            db.select("TravelAppTrips", {
                select: "id,name,destination",
                id: `eq.${tripId}`,
                limit: "1",
            }),
            db.select("TravelAppMembers", {
                select: "id,display_name",
                trip_id: `eq.${tripId}`,
            }),
            db.select("TravelAppExpenses", {
                select: "id,paid_by_member,amount_money,title,category",
                trip_id: `eq.${tripId}`,
            }),
        ]);

        const trip = trips[0] ?? null;

        /** @type {Map<string, string>} */
        const memberNameMap = new Map(
            allMembers.map((m) => [m.id, m.display_name])
        );

        let splits = [];
        if (expenses.length > 0) {
            const expenseIds = expenses.map((e) => e.id).join(",");
            splits = await db.select("TravelAppSplits", {
                select: "id,expense_id,member_id,share_money,is_settled",
                expense_id: `in.(${expenseIds})`,
            });
        }

        const balance = computeBalance(
            member.id,
            expenses,
            splits,
            memberNameMap
        );

        return res.status(200).json({
            memberName: member.display_name,
            tripName: trip?.name ?? "Trip",
            tripDestination: trip?.destination ?? null,
            memberCount: allMembers.length,
            expenseCount: expenses.length,
            ...balance,
        });
    } catch (err) {
        console.error("[guest] Unexpected error:", err);
        return res.status(500).json({ error: "Something went wrong" });
    }
}