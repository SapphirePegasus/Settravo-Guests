/**
 * api/guest.js — Vercel serverless function
 *
 * GET /api/guest?token=<uuid>
 *
 * Validates the guest_token, fetches the member's trip + settlement data,
 * and returns it as JSON. The guest webpage calls this on load.
 *
 * Security:
 *  - SUPABASE_SERVICE_ROLE_KEY is a Vercel environment secret — never
 *    exposed to the browser. Set it in Vercel project settings under
 *    Settings → Environment Variables.
 *  - guest_token is a UUID v4 (2^122 entropy). Not guessable.
 *  - Returns ONLY the requesting member's own balance data.
 *  - Rate limited: 30 requests per IP per minute (in-memory sliding window).
 *    Vercel's own infra handles DDoS above this layer.
 *  - CORS locked to your domain only. No wildcard.
 *  - UUID format is validated with a strict regex before touching the DB.
 *    This prevents SQL injection patterns and wastes no DB round-trips on
 *    obviously invalid tokens.
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
 * Compute a simplified per-person net balance for `myMemberId`.
 *
 * Returns:
 *  - iOweDetails: people this member owes money to
 *  - owedToMeDetails: people who owe this member money
 *  - iPaid: total paise this member paid across all expenses
 *  - iOwe: total paise this member owes across all splits
 *  - myNet: positive = others owe me, negative = I owe others
 *
 * All arithmetic is integer paise — no floating point.
 *
 * @param {string} myMemberId
 * @param {any[]} expenses
 * @param {any[]} splits
 * @param {Map<string, string>} memberNameMap  memberId → displayName
 */
function computeBalance(myMemberId, expenses, splits, memberNameMap) {
    let iPaid = 0;
    let iOwe = 0;

    for (const expense of expenses) {
        if (expense.paid_by_member === myMemberId) {
            iPaid += expense.amount_money;
        }
    }

    for (const split of splits) {
        if (split.member_id === myMemberId) {
            iOwe += split.share_money;
        }
    }

    const myNet = iPaid - iOwe;

    /** @type {Map<string, number>} net amount with each other member */
    const netWithMember = new Map();

    for (const expense of expenses) {
        const payer = expense.paid_by_member;
        const expenseSplits = splits.filter((s) => s.expense_id === expense.id);

        for (const split of expenseSplits) {
            const debtor = split.member_id;
            if (debtor === payer) continue;

            if (debtor === myMemberId) {
                const cur = netWithMember.get(payer) ?? 0;
                netWithMember.set(payer, cur - split.share_money);
            } else if (payer === myMemberId) {
                const cur = netWithMember.get(debtor) ?? 0;
                netWithMember.set(debtor, cur + split.share_money);
            }
        }
    }

    /** @type {{ toName: string; amount: number }[]} */
    const iOweDetails = [];
    /** @type {{ fromName: string; amount: number }[]} */
    const owedToMeDetails = [];

    for (const [otherId, net] of netWithMember.entries()) {
        const otherName = memberNameMap.get(otherId) ?? otherId;
        if (net < 0) {
            iOweDetails.push({ toName: otherName, amount: Math.abs(net) });
        } else if (net > 0) {
            owedToMeDetails.push({ fromName: otherName, amount: net });
        }
    }

    return { iPaid, iOwe, myNet, iOweDetails, owedToMeDetails };
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
            ...balance,
        });
    } catch (err) {
        console.error("[guest] Unexpected error:", err);
        return res.status(500).json({ error: "Something went wrong" });
    }
}