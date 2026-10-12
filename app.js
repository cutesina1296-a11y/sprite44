"use strict";

const path = require("node:path");
const fs = require("node:fs");
const {
    createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, randomInt, timingSafeEqual
} = require("node:crypto");
const bcrypt = require("bcryptjs");
const express = require("express");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const helmet = require("helmet");
const { models, nextId, withTransaction } = require("./database");
const signupBonusPaise = 4000;
const withdrawalUnlockProductId = 388;

const spinPrizes = [
    { code: "cash_5", label: "₹5", type: "cash", value: 5, amountPaise: 500, weight: 22, wheelIndices: [0, 4] },
    { code: "cash_10", label: "₹10", type: "cash", value: 10, amountPaise: 1000, weight: 18, wheelIndices: [1, 5] },
    { code: "cash_15", label: "₹15", type: "cash", value: 15, amountPaise: 1500, weight: 15, wheelIndices: [2] },
    { code: "cash_50", label: "₹50", type: "cash", value: 50, amountPaise: 5000, weight: 10, wheelIndices: [3] },
    { code: "locked", label: "Locked", type: "lose", value: 0, amountPaise: 0, weight: 25, wheelIndices: [7] }
];
const totalSpinPrizeWeight = spinPrizes.reduce((total, prize) => total + prize.weight, 0);

const isProduction = process.env.NODE_ENV === "production";
const dataDirectory = path.join(__dirname, ".private");
fs.mkdirSync(dataDirectory, { recursive: true });
const developmentSecretPath = path.join(dataDirectory, "session-secret");
let developmentSecret = "";
if (!isProduction && !process.env.SESSION_SECRET) {
    developmentSecret = fs.existsSync(developmentSecretPath)
        ? fs.readFileSync(developmentSecretPath, "utf8").trim()
        : "";
    if (!developmentSecret) {
        developmentSecret = randomBytes(48).toString("hex");
        try {
            fs.writeFileSync(developmentSecretPath, developmentSecret, { flag: "wx" });
        } catch (error) {
            if (error.code !== "EEXIST") throw error;
            developmentSecret = fs.readFileSync(developmentSecretPath, "utf8").trim();
        }
    }
}
const sessionSecret = process.env.SESSION_SECRET || (isProduction ? "" : developmentSecret);
if (!sessionSecret) throw new Error("SESSION_SECRET must be configured in production.");
if (!process.env.SESSION_SECRET && !isProduction) {
    console.warn("SESSION_SECRET is unset; using the private persistent local-development secret.");
}
if (sessionSecret.length < 32) throw new Error("SESSION_SECRET must contain at least 32 characters.");

const bankEncryptionKeyPath = path.join(dataDirectory, "bank-details-key");
let bankEncryptionKey = process.env.BANK_DETAILS_ENCRYPTION_KEY || "";
if (!isProduction && !bankEncryptionKey) {
    bankEncryptionKey = fs.existsSync(bankEncryptionKeyPath)
        ? fs.readFileSync(bankEncryptionKeyPath, "utf8").trim()
        : "";
    if (!bankEncryptionKey) {
        bankEncryptionKey = randomBytes(32).toString("hex");
        try {
            fs.writeFileSync(bankEncryptionKeyPath, bankEncryptionKey, { flag: "wx", mode: 0o600 });
        } catch (error) {
            if (error.code !== "EEXIST") throw error;
            bankEncryptionKey = fs.readFileSync(bankEncryptionKeyPath, "utf8").trim();
        }
    }
}
if (!/^[a-f0-9]{64}$/i.test(bankEncryptionKey)) {
    throw new Error("BANK_DETAILS_ENCRYPTION_KEY must be a 64-character hexadecimal key.");
}
bankEncryptionKey = Buffer.from(bankEncryptionKey, "hex");

const app = express();
const port = Number(process.env.PORT || 3000);
const configuredPaymentProvider = (process.env.PAYMENT_PROVIDER || "manual").toLowerCase();
const paymentProvider = ["razorpay", "mock", "watchpays"].includes(configuredPaymentProvider)
    ? configuredPaymentProvider
    : "manual";
if (isProduction && paymentProvider === "mock") {
    throw new Error("The mock payment provider is available only outside production.");
}
const razorpayKeyId = process.env.RAZORPAY_KEY_ID || "";
const razorpayKeySecret = process.env.RAZORPAY_KEY_SECRET || "";
const razorpayEnabled = paymentProvider === "razorpay" && Boolean(razorpayKeyId) && Boolean(razorpayKeySecret);
const mockPaymentEnabled = !isProduction && paymentProvider === "mock";
const watchPaysMerchantId = process.env.WATCHPAYS_MERCHANT_ID || "";
const watchPaysApiKey = process.env.WATCHPAYS_API_KEY || "";
const watchPaysCallbackUrl = process.env.WATCHPAYS_PAYIN_CALLBACK_URL || "";
const watchPaysApiUrl = process.env.WATCHPAYS_PAYIN_URL || "https://api.watchpays.com/v1/create";
let watchPaysApiUrlIsValid = false;
try {
    const parsed = new URL(watchPaysApiUrl);
    watchPaysApiUrlIsValid = parsed.protocol === "https:"
        && parsed.hostname === "api.watchpays.com"
        && parsed.pathname === "/v1/create"
        && !parsed.username && !parsed.password;
} catch {}
let watchPaysCallbackUrlIsValid = false;
try {
    const parsed = new URL(watchPaysCallbackUrl);
    watchPaysCallbackUrlIsValid = parsed.protocol === "https:"
        && parsed.pathname === "/api/recharge/watchpays/callback"
        && !parsed.username && !parsed.password;
} catch {}
const watchPaysEnabled = paymentProvider === "watchpays"
    && Boolean(watchPaysMerchantId && watchPaysApiKey)
    && watchPaysApiUrlIsValid && watchPaysCallbackUrlIsValid;
const mediaDirectory = path.join(__dirname, "uploads", "media");
fs.mkdirSync(mediaDirectory, { recursive: true });
const dummyPasswordHash = bcrypt.hashSync(randomBytes(32).toString("hex"), 12);

function asyncRoute(handler) {
    return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

class MongoSessionStore extends session.Store {
    get(sid, callback) {
        models.Session.findOne({ sid, expiresAt: { $gt: new Date() } }).lean()
            .then(record => callback(null, record ? record.data : null))
            .catch(callback);
    }

    set(sid, value, callback) {
        const expiresAt = value.cookie && value.cookie.expires
            ? new Date(value.cookie.expires)
            : new Date(Date.now() + 24 * 60 * 60 * 1000);
        models.Session.updateOne(
            { sid },
            { $set: { sid, data: value, expiresAt } },
            { upsert: true }
        ).then(() => callback(null)).catch(callback);
    }

    touch(sid, value, callback) {
        const expiresAt = value.cookie && value.cookie.expires
            ? new Date(value.cookie.expires)
            : new Date(Date.now() + 24 * 60 * 60 * 1000);
        models.Session.updateOne({ sid }, { $set: { expiresAt } })
            .then(() => callback(null)).catch(callback);
    }

    destroy(sid, callback) {
        models.Session.deleteOne({ sid })
            .then(() => callback(null)).catch(callback);
    }
}

const sessionStore = new MongoSessionStore();
app.disable("x-powered-by");
if (isProduction) app.set("trust proxy", 1);
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"], baseUri: ["'self'"], connectSrc: ["'self'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"], formAction: ["'self'"],
            frameAncestors: ["'none'"], imgSrc: ["'self'", "data:", "https://img.icons8.com"],
            scriptSrc: ["'self'", "'unsafe-inline'"], scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"]
        }
    }
}));
app.use(express.json({ limit: "10kb" }));
app.use(session({
    name: "kingfisher.sid",
    secret: sessionSecret,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, secure: isProduction, sameSite: "strict",
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.get("/health", (req, res) => {
    const mongoose = require("mongoose");
    const connected = mongoose.connection.readyState === 1;
    res.status(connected ? 200 : 503).json({ status: connected ? "ok" : "unavailable" });
});

app.use(asyncRoute(async (req, res, next) => {
    const maintenanceSetting = await models.SiteSetting.findOne({ key: "maintenance_mode" }).select("value").lean();
    const maintenanceMode = maintenanceSetting && maintenanceSetting.value === "true";
    if (!maintenanceMode
        || req.path === "/admin" || req.path === "/admin.html"
        || req.path === "/api/admin" || req.path.startsWith("/api/admin/")
        || req.path === "/api/csrf" || req.path === "/api/logout"
        || req.path === "/api/recharge/watchpays/callback"
        || req.path === "/health" || req.path.startsWith("/assets/") || req.path.startsWith("/uploads/")) {
        return next();
    }
    res.set("Cache-Control", "no-store");
    res.set("Retry-After", "60");
    if (req.path.startsWith("/api/")) {
        return res.status(503).json({
            success: false,
            message: "The site is temporarily unavailable for maintenance."
        });
    }
    res.status(503).type("html").send(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\">" +
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
        "<title>Maintenance · Finora</title><body style=\"font:16px system-ui,sans-serif;max-width:560px;margin:15vh auto;padding:24px;color:#344054\">" +
        "<h1>We’ll be back soon</h1><p>The site is temporarily unavailable while maintenance is in progress. Please try again shortly.</p>" +
        "</body></html>"
    );
}));

function createCsrfToken() {
    return randomBytes(32).toString("hex");
}

function tokenMatches(expected, supplied) {
    if (typeof supplied !== "string" || !/^[a-f0-9]{64}$/i.test(supplied)) return false;
    const expectedBuffer = Buffer.from(expected, "hex");
    const suppliedBuffer = Buffer.from(supplied, "hex");
    return expectedBuffer.length === suppliedBuffer.length
        && timingSafeEqual(expectedBuffer, suppliedBuffer);
}

function requireCsrf(req, res, next) {
    if (!req.session.csrfToken
        || !tokenMatches(req.session.csrfToken, req.get("X-CSRF-Token"))) {
        return res.status(403).json({ success: false, message: "Session expired. Refresh and try again." });
    }
    next();
}

function credentialVersionMatches(identity, account) {
    const sessionVersion = Number.isSafeInteger(identity.credentialVersion) ? identity.credentialVersion : 0;
    const accountVersion = Number.isSafeInteger(account.credentialVersion) ? account.credentialVersion : 0;
    return sessionVersion === accountVersion;
}

async function destroySession(req, res) {
    await new Promise((resolve, reject) => req.session.destroy(error => error ? reject(error) : resolve()));
    res.clearCookie("kingfisher.sid", {
        httpOnly: true, secure: isProduction, sameSite: "strict"
    });
}

async function restoreAdminSession(req) {
    const admin = await models.Admin.findOne({ id: req.session.admin.id })
        .select("credentialVersion").lean();
    if (!admin || !credentialVersionMatches(req.session.admin, admin)) return false;
    delete req.session.user;
    delete req.session.impersonation;
    req.session.csrfToken = createCsrfToken();
    await new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
    return true;
}

const requireAuth = asyncRoute(async (req, res, next) => {
    if (!req.session.user) {
        return res.status(401).json({ success: false, message: "Please log in first." });
    }
    const user = await models.User.findOne({ id: req.session.user.id })
        .select("status credentialVersion").lean();
    const accountUnavailable = !user || user.status !== "active";
    if (accountUnavailable || !credentialVersionMatches(req.session.user, user)) {
        if (req.session.impersonation && req.session.admin) {
            if (await restoreAdminSession(req)) {
                return res.status(401).json({
                    success: false,
                    message: accountUnavailable
                        ? "This user account is unavailable. Admin access has been restored."
                        : "This user session is no longer valid. Admin access has been restored."
                });
            }
        }
        await destroySession(req, res);
        return res.status(401).json({
            success: false,
            message: accountUnavailable ? "This account is unavailable." : "This session is no longer valid."
        });
    }
    next();
});

const requireAdmin = asyncRoute(async (req, res, next) => {
    if (!req.session.admin) {
        return res.status(401).json({ success: false, message: "Admin login required." });
    }
    const admin = await models.Admin.findOne({ id: req.session.admin.id })
        .select("credentialVersion passwordChangeRequired").lean();
    if (!admin || !credentialVersionMatches(req.session.admin, admin)) {
        await destroySession(req, res);
        return res.status(401).json({ success: false, message: "Admin session expired. Please log in again." });
    }
    req.adminAccount = admin;
    next();
});

async function auditAdmin(adminId, action, entityType, entityId, details, session = null) {
    const audit = {
        id: await nextId("admin_audit"),
        adminId,
        action,
        entityType,
        entityId: String(entityId || ""),
        details: details || {}
    };
    if (session) {
        await models.AdminAudit.create([audit], { session });
    } else {
        await models.AdminAudit.create(audit);
    }
}

function parseRupees(value) {
    const amount = typeof value === "number" ? value : Number(value);
    if (!Number.isFinite(amount) || Math.abs(amount) > 10000000) return null;
    const paise = Math.round(amount * 100);
    return Number.isSafeInteger(paise) ? paise : null;
}

function encryptBankAccount(accountNumber) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", bankEncryptionKey, iv);
    const ciphertext = Buffer.concat([cipher.update(accountNumber, "utf8"), cipher.final()]);
    return {
        ciphertext: ciphertext.toString("hex"),
        iv: iv.toString("hex"),
        tag: cipher.getAuthTag().toString("hex")
    };
}

function decryptBankAccount(record) {
    const decipher = createDecipheriv("aes-256-gcm", bankEncryptionKey, Buffer.from(record.accountIv, "hex"));
    decipher.setAuthTag(Buffer.from(record.accountTag, "hex"));
    return Buffer.concat([
        decipher.update(Buffer.from(record.accountCiphertext, "hex")),
        decipher.final()
    ]).toString("utf8");
}

async function createReferralCode() {
    let code;
    do {
        code = randomBytes(5).toString("hex").toUpperCase();
    } while (await models.User.exists({ referralCode: code }));
    return code;
}

async function settingValue(key, fallback = "") {
    const setting = await models.SiteSetting.findOne({ key }).select("value").lean();
    return setting ? setting.value : fallback;
}

function getPaymentGatewayConfig() {
    return {
        provider: paymentProvider,
        enabled: razorpayEnabled || mockPaymentEnabled || watchPaysEnabled,
        mode: mockPaymentEnabled ? "test" : (razorpayEnabled || watchPaysEnabled) ? "live" : "manual"
    };
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, { ...options, signal: controller.signal });
    } catch (error) {
        if (error.name === "AbortError") {
            throw new Error("Gateway request timed out. Check the network and credentials.");
        }
        throw error;
    } finally {
        clearTimeout(timer);
    }
}

async function createRazorpayOrder({ amountPaise, userId, receipt }) {
    if (!razorpayEnabled) throw new Error("Razorpay is not configured.");
    const response = await fetchWithTimeout("https://api.razorpay.com/v1/orders", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Basic ${Buffer.from(`${razorpayKeyId}:${razorpayKeySecret}`).toString("base64")}`
        },
        body: JSON.stringify({
            amount: Math.max(1, Number(amountPaise)), currency: "INR", receipt,
            notes: { userId: String(userId) }
        })
    });
    const result = await response.json();
    if (!response.ok || !result.id) {
        throw new Error(result?.error?.description || result?.message || "Could not create Razorpay order.");
    }
    return result;
}

function createWatchPaysSignature(params, apiKey) {
    const signString = Object.keys(params)
        .filter(key => params[key] !== "" && params[key] !== null && params[key] !== undefined)
        .sort()
        .map(key => `${key}=${params[key]}`)
        .concat(`key=${apiKey}`)
        .join("&");
    return createHash("md5").update(signString, "utf8").digest("hex");
}

async function createWatchPaysOrder({ amountPaise, merchantOrderNo }) {
    if (!watchPaysEnabled) {
        throw new Error("WatchPays is not fully configured. Check the provider credentials and public HTTPS callback URL.");
    }
    const params = {
        merchant_id: watchPaysMerchantId,
        amount: (amountPaise / 100).toFixed(2),
        merchant_order_no: merchantOrderNo,
        callback_url: watchPaysCallbackUrl
    };
    const response = await fetchWithTimeout(watchPaysApiUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            ...params,
            api_key: watchPaysApiKey,
            signature: createWatchPaysSignature(params, watchPaysApiKey)
        })
    });
    let result;
    try {
        result = await response.json();
    } catch {
        throw new Error("WatchPays returned an invalid response.");
    }
    let paymentUrl;
    try {
        paymentUrl = new URL(result.payment_url);
    } catch {
        throw new Error("WatchPays did not return a valid checkout URL.");
    }
    if (!response.ok || result.success !== true || result.merchant_order_no !== merchantOrderNo
        || typeof result.order_no !== "string" || !result.order_no
        || parseRupees(result.amount) !== amountPaise || paymentUrl.protocol !== "https:") {
        throw new Error("WatchPays could not confirm the checkout order.");
    }
    return { paymentUrl: paymentUrl.toString(), gatewayOrderNo: result.order_no };
}

function verifyRazorpaySignature({ orderId, paymentId, signature }) {
    if (!razorpayEnabled || !orderId || !paymentId || !signature) return false;
    const generated = createHmac("sha256", razorpayKeySecret)
        .update(`${orderId}|${paymentId}`)
        .digest("hex");
    if (generated.length !== signature.length) return false;
    return timingSafeEqual(Buffer.from(generated, "utf8"), Buffer.from(signature, "utf8"));
}

async function descendantsOf(userId, maxDepth = Infinity) {
    const descendants = [];
    const visited = new Set([userId]);
    let parentIds = [userId];
    for (let level = 1; parentIds.length && level <= maxDepth; level += 1) {
        const children = await models.User.find({ referredByUserId: { $in: parentIds } })
            .select("id status referredByUserId").lean();
        const nextParentIds = [];
        for (const user of children) {
            if (visited.has(user.id)) continue;
            visited.add(user.id);
            descendants.push({ user, level });
            nextParentIds.push(user.id);
        }
        parentIds = nextParentIds;
    }
    return descendants;
}

async function countActiveTeamMembers(userId) {
    return (await descendantsOf(userId, 3)).filter(item => item.user.status === "active").length;
}

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: "draft-7", legacyHeaders: false,
    message: { success: false, message: "Too many attempts. Please try again later." }
});
const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: "draft-7", legacyHeaders: false,
    message: { success: false, message: "Too many admin login attempts. Try again later." }
});

app.get("/api/csrf", asyncRoute(async (req, res) => {
    if (!req.session.csrfToken) req.session.csrfToken = createCsrfToken();
    res.set("Cache-Control", "no-store");
    res.json({ csrfToken: req.session.csrfToken });
}));

app.get("/api/public/settings", asyncRoute(async (req, res) => {
    const keys = [
        "site_name", "site_logo_url", "site_banner_url", "invite_banner_url", "site_spinner_url",
        "minimum_withdrawal_rupees", "support_url",
        "welcome_popup_title", "welcome_popup_subtitle",
        "welcome_popup_signup_reward_label", "welcome_popup_signup_reward_value",
        "welcome_popup_invite_tracking_label", "welcome_popup_invite_tracking_value",
        "welcome_popup_min_withdrawal_label", "welcome_popup_min_recharge_label",
        "welcome_popup_payout_processing_label", "welcome_popup_payout_processing_value",
        "welcome_popup_cta_text", "welcome_popup_close_label"
    ];
    const settings = await models.SiteSetting.find({ key: { $in: keys } }).select("key value").lean();
    const gateway = getPaymentGatewayConfig();
    res.set("Cache-Control", "no-store");
    res.json({
        success: true,
        settings: Object.assign({
            payment_provider: gateway.provider,
            payment_gateway_enabled: gateway.enabled ? "1" : "0",
            payment_gateway_mode: gateway.mode
        }, Object.fromEntries(settings.map(setting => [setting.key, setting.value])))
    });
}));

async function siteImagePath(settingKey, fallbackFilename) {
    const imageUrl = await settingValue(settingKey);
    let imagePath;
    if (/^\/uploads\/media\/[a-f0-9]{32}\.(?:png|jpg|webp)$/.test(imageUrl)) {
        imagePath = path.join(mediaDirectory, path.basename(imageUrl));
    } else if (/^\/assets\/images\/[a-zA-Z0-9_-]+\.(?:svg|png|jpe?g|webp)$/.test(imageUrl)) {
        imagePath = path.join(__dirname, "assets", "images", path.basename(imageUrl));
    }
    if (!imagePath || !fs.existsSync(imagePath)) {
        imagePath = path.join(__dirname, "assets", "images", fallbackFilename);
    }
    return imagePath;
}
app.get("/site-logo", asyncRoute(async (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(await siteImagePath("site_logo_url", "sprite-logo.png"));
}));
app.get("/site-banner", asyncRoute(async (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(await siteImagePath("site_banner_url", "money-hero.png"));
}));

app.post("/api/register", authLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    const phone = typeof req.body.phone === "string" ? req.body.phone : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const referralCode = typeof req.body.referralCode === "string"
        ? req.body.referralCode.trim().toUpperCase() : "";
    if (!name || name.length > 50) {
        return res.status(400).json({ success: false, message: "Enter a name up to 50 characters." });
    }
    if (!/^\d{10}$/.test(phone)) {
        return res.status(400).json({ success: false, message: "Enter a valid 10 digit mobile number." });
    }
    if (password.length < 6 || password.length > 64) {
        return res.status(400).json({ success: false, message: "Password must be 6 to 64 characters." });
    }
    if (referralCode && !/^[A-F0-9]{10}$/.test(referralCode)) {
        return res.status(400).json({ success: false, message: "Invalid invite code." });
    }
    const referrer = referralCode ? await models.User.findOne({ referralCode }).select("id").lean() : null;
    if (referralCode && !referrer) {
        return res.status(400).json({ success: false, message: "This invite code is not valid." });
    }
    try {
        await withTransaction(async dbSession => {
            const [user] = await models.User.create([{
                id: await nextId("users", dbSession),
                name,
                phone,
                passwordHash: await bcrypt.hash(password, 12),
                balancePaise: signupBonusPaise,
                referralCode: await createReferralCode(),
                referredByUserId: referrer ? referrer.id : null
            }], { session: dbSession });
            await models.WalletTransaction.create([{
                id: await nextId("wallet_transactions", dbSession),
                userId: user.id,
                type: "adjustment",
                amountPaise: signupBonusPaise,
                status: "approved",
                note: "Signup bonus",
                reviewedAt: new Date()
            }], { session: dbSession });
        });
    } catch (error) {
        if (error.code === 11000 && (error.keyPattern?.phone || error.keyValue?.phone)) {
            return res.status(409).json({
                success: false,
                message: "An account with this mobile number already exists."
            });
        }
        throw error;
    }
    res.status(201).json({
        success: true, message: "Account created successfully. ₹40 signup bonus added to your wallet."
    });
}));

app.post("/api/login", authLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const phone = typeof req.body.phone === "string" ? req.body.phone : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (!/^\d{10}$/.test(phone) || !password || password.length > 64) {
        return res.status(400).json({ success: false, message: "Enter a valid mobile number and password." });
    }
    const user = await models.User.findOne({ phone }).lean();
    const passwordMatches = user
        ? await bcrypt.compare(password, user.passwordHash)
        : await bcrypt.compare(password, dummyPasswordHash);
    if (!user || user.status !== "active" || !passwordMatches) {
        return res.status(401).json({ success: false, message: "Invalid mobile number or password." });
    }
    await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
    req.session.user = {
        id: user.id, name: user.name, phone: user.phone, credentialVersion: user.credentialVersion || 0
    };
    req.session.csrfToken = createCsrfToken();
    await new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
    res.json({ success: true, message: "Login successful.", csrfToken: req.session.csrfToken });
}));

app.get("/api/session", asyncRoute(async (req, res) => {
    res.set("Cache-Control", "no-store");
    if (!req.session.user) return res.status(401).json({ success: false, message: "Not logged in." });
    const user = await models.User.findOne({ id: req.session.user.id })
        .select("id name phone status balancePaise referralCode credentialVersion").lean();
    const accountUnavailable = !user || user.status !== "active";
    if (accountUnavailable || !credentialVersionMatches(req.session.user, user)) {
        if (req.session.impersonation && req.session.admin && await restoreAdminSession(req)) {
            return res.status(401).json({
                success: false,
                message: accountUnavailable
                    ? "This user account is unavailable. Admin access has been restored."
                    : "This user session is no longer valid. Admin access has been restored."
            });
        }
        await destroySession(req, res);
        return res.status(401).json({
            success: false,
            message: accountUnavailable ? "This account is unavailable." : "This session is no longer valid."
        });
    }
    res.json({
        success: true,
        user: {
            id: user.id, name: user.name, phone: user.phone, status: user.status,
            balancePaise: user.balancePaise, referralCode: user.referralCode
        }
    });
}));

app.post("/api/logout", requireCsrf, asyncRoute(async (req, res) => {
    if (req.session.impersonation) {
        return res.status(403).json({
            success: false,
            message: "Use the support access banner to return to admin."
        });
    }
    await new Promise((resolve, reject) => req.session.destroy(error => error ? reject(error) : resolve()));
    res.clearCookie("kingfisher.sid", {
        httpOnly: true, secure: isProduction, sameSite: "strict"
    });
    res.json({ success: true, message: "Logged out." });
}));

app.post("/api/products/purchase", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    const productId = Number.parseInt(req.body.productId, 10);
    if (!Number.isSafeInteger(productId) || productId < 1) {
        return res.status(400).json({ success: false, message: "Choose a valid product." });
    }
    const outcome = await withTransaction(async dbSession => {
        const product = await models.Product.findOne({ id: productId, active: true }).session(dbSession).lean();
        if (!product) return { error: "This product is no longer available.", status: 404 };
        const purchasedCount = await models.UserProduct.countDocuments({
            userId: req.session.user.id, productId
        }).session(dbSession);
        if (purchasedCount >= product.purchaseLimit) {
            return { error: "You have reached the purchase limit for this product.", status: 409 };
        }
        const updatedUser = await models.User.findOneAndUpdate({
            id: req.session.user.id,
            $expr: {
                $gte: ["$balancePaise", { $add: ["$reservedWithdrawalPaise", product.pricePaise] }]
            }
        }, { $inc: { balancePaise: -product.pricePaise } }, { new: true, session: dbSession });
        if (!updatedUser) {
            return {
                error: "Insufficient available wallet balance. Complete a verified recharge first.",
                status: 400
            };
        }
        const purchaseId = await nextId("user_products", dbSession);
        await models.UserProduct.create([{
            id: purchaseId,
            userId: req.session.user.id,
            productId,
            productName: product.name,
            pricePaise: product.pricePaise,
            durationDays: product.durationDays,
            expiresAt: new Date(Date.now() + product.durationDays * 24 * 60 * 60 * 1000)
        }], { session: dbSession });
        if (product.pricePaise > 0) {
            await models.WalletTransaction.create([{
                id: await nextId("wallet_transactions", dbSession),
                userId: req.session.user.id,
                type: "adjustment",
                amountPaise: -product.pricePaise,
                status: "approved",
                note: `Product purchase #${purchaseId}: ${product.name}`,
                reviewedAt: new Date()
            }], { session: dbSession });
        }
        return { purchaseId, productName: product.name, pricePaise: product.pricePaise };
    });
    if (outcome.error) {
        return res.status(outcome.status).json({ success: false, message: outcome.error });
    }
    res.status(201).json({
        success: true,
        ...outcome,
        message: `${outcome.productName} is active. ₹${(outcome.pricePaise / 100).toFixed(2)} was deducted from the internal wallet. One spin has been added for this plan purchase.`
    });
}));

app.get("/api/my-products", requireAuth, asyncRoute(async (req, res) => {
    const purchased = await models.UserProduct.find({ userId: req.session.user.id })
        .sort({ id: -1 }).limit(100).lean();
    const productIds = [...new Set(purchased.map(item => item.productId))];
    const productsById = new Map((await models.Product.find({ id: { $in: productIds } })
        .select("id imageUrl").lean()).map(item => [item.id, item]));
    const products = purchased.map(item => ({
        id: item.id,
        productId: item.productId,
        productName: item.productName,
        pricePaise: item.pricePaise,
        durationDays: item.durationDays,
        purchasedAt: item.purchasedAt,
        expiresAt: item.expiresAt,
        status: item.expiresAt <= new Date() ? "expired" : item.status,
        imageUrl: (productsById.get(item.productId) || {}).imageUrl || ""
    }));
    res.set("Cache-Control", "no-store");
    res.json({ success: true, products });
}));

app.get("/api/bank-account", requireAuth, asyncRoute(async (req, res) => {
    const account = await models.BankAccount.findOne({ userId: req.session.user.id })
        .select("holderName bankName accountLast4 ifsc updatedAt").lean();
    res.set("Cache-Control", "no-store");
    res.json({ success: true, account: account || null });
}));

app.put("/api/bank-account", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    const holderName = typeof req.body.holderName === "string" ? req.body.holderName.trim() : "";
    const bankName = typeof req.body.bankName === "string" ? req.body.bankName.trim() : "";
    const accountNumber = typeof req.body.accountNumber === "string"
        ? req.body.accountNumber.replace(/\s+/g, "") : "";
    const ifsc = typeof req.body.ifsc === "string" ? req.body.ifsc.trim().toUpperCase() : "";
    if (!holderName || holderName.length > 80 || !bankName || bankName.length > 80
        || !/^\d{8,18}$/.test(accountNumber) || !/^[A-Z]{4}0[A-Z0-9]{6}$/.test(ifsc)) {
        return res.status(400).json({
            success: false,
            message: "Enter a valid account holder, bank, 8–18 digit account number and IFSC code."
        });
    }
    if (await models.WalletTransaction.exists({
        userId: req.session.user.id, type: "withdrawal", status: { $in: ["pending", "processing"] }
    })) {
        return res.status(409).json({
            success: false,
            message: "Bank details cannot be changed while a withdrawal is pending."
        });
    }
    const encrypted = encryptBankAccount(accountNumber);
    await models.BankAccount.updateOne(
        { userId: req.session.user.id },
        { $set: {
            userId: req.session.user.id, holderName, bankName,
            accountCiphertext: encrypted.ciphertext, accountIv: encrypted.iv,
            accountTag: encrypted.tag, accountLast4: accountNumber.slice(-4), ifsc
        } },
        { upsert: true }
    );
    res.json({
        success: true,
        account: { holderName, bankName, accountLast4: accountNumber.slice(-4), ifsc },
        message: "Bank details saved encrypted. Only the last four account digits are shown in your profile."
    });
}));

app.post("/api/recharge", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    const amountPaise = parseRupees(req.body.amount);
    const method = typeof req.body.method === "string" ? req.body.method.trim().slice(0, 40) : "";
    if (!amountPaise || amountPaise <= 0 || !method) {
        return res.status(400).json({ success: false, message: "Enter a valid amount and payment channel." });
    }
    if (paymentProvider === "watchpays" && !watchPaysEnabled) {
        return res.status(503).json({
            success: false,
            message: "WatchPays is not fully configured. Check the provider credentials and public HTTPS callback URL."
        });
    }
    let reference = method;
    let note = "Submitted for manual verification";
    let gateway;
    let merchantOrderNo;
    if (mockPaymentEnabled) {
        reference = `local-mock-${randomBytes(16).toString("hex")}`;
        note = "Local test checkout; no real payment";
    } else if (razorpayEnabled) {
        const receipt = `recharge-${Date.now()}-${req.session.user.id}`;
        gateway = await createRazorpayOrder({ amountPaise, userId: req.session.user.id, receipt });
        reference = gateway.id;
        note = "Waiting for gateway payment confirmation";
    } else if (paymentProvider === "watchpays") {
        merchantOrderNo = `watchpays-${Date.now()}-${randomBytes(8).toString("hex")}`;
        reference = merchantOrderNo;
        note = "WatchPays checkout is being created; wallet credit requires admin review";
    }
    const transactionId = await nextId("wallet_transactions");
    await models.WalletTransaction.create({
        id: transactionId,
        userId: req.session.user.id,
        type: "recharge",
        amountPaise,
        status: "pending",
        reference,
        note
    });
    if (mockPaymentEnabled) {
        return res.status(201).json({
            success: true, gateway: "mock", transactionId, orderId: reference,
            paymentUrl: `/mock-checkout.html?transactionId=${transactionId}`,
            message: "Local test checkout created. No real payment will be made."
        });
    }
    if (razorpayEnabled) {
        return res.json({
            success: true, gateway: "razorpay", transactionId, orderId: gateway.id,
            amount: amountPaise, currency: "INR", keyId: razorpayKeyId,
            message: "Secure payment checkout opened. Complete the payment to credit your wallet."
        });
    }
    if (merchantOrderNo) {
        try {
            gateway = await createWatchPaysOrder({ amountPaise, merchantOrderNo });
        } catch (error) {
            console.error("WatchPays order creation failed:", error.name);
            await models.WalletTransaction.updateOne(
                { id: transactionId, status: "pending" },
                { $set: { note: "WatchPays checkout could not be confirmed. Verify provider status before admin review." } }
            );
            return res.status(502).json({
                success: false, transactionId,
                message: "Could not confirm WatchPays checkout creation. The recharge remains pending for admin review."
            });
        }
        await models.WalletTransaction.updateOne(
            { id: transactionId, status: "pending" },
            { $set: { note: "WatchPays checkout created; verify receipt in provider dashboard before admin approval" } }
        );
        return res.status(201).json({
            success: true, gateway: "watchpays", transactionId, orderId: merchantOrderNo,
            paymentUrl: gateway.paymentUrl,
            message: "WatchPays checkout created. Wallet credit requires admin verification."
        });
    }
    res.status(202).json({
        success: true, transactionId,
        message: "Recharge request submitted for admin review. No balance has been credited yet."
    });
}));

app.get("/api/recharge/mock/:id", requireAuth, asyncRoute(async (req, res) => {
    if (!mockPaymentEnabled) {
        return res.status(404).json({ success: false, message: "Local test checkout is not enabled." });
    }
    const transactionId = Number.parseInt(req.params.id, 10);
    if (!Number.isSafeInteger(transactionId) || transactionId < 1) {
        return res.status(400).json({ success: false, message: "Invalid test checkout." });
    }
    const transaction = await models.WalletTransaction.findOne({
        id: transactionId, userId: req.session.user.id, type: "recharge",
        reference: /^local-mock-/
    }).select("id amountPaise status").lean();
    if (!transaction) {
        return res.status(404).json({ success: false, message: "Test checkout could not be found." });
    }
    res.set("Cache-Control", "no-store");
    res.json({ success: true, transaction });
}));

app.post("/api/recharge/mock/:id/complete", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    if (!mockPaymentEnabled) {
        return res.status(404).json({ success: false, message: "Local test checkout is not enabled." });
    }
    const transactionId = Number.parseInt(req.params.id, 10);
    if (!Number.isSafeInteger(transactionId) || transactionId < 1) {
        return res.status(400).json({ success: false, message: "Invalid test checkout." });
    }
    const result = await withTransaction(async dbSession => {
        const transaction = await models.WalletTransaction.findOne({
            id: transactionId, userId: req.session.user.id, type: "recharge",
            reference: /^local-mock-/
        }).session(dbSession).lean();
        if (!transaction) return { error: "Test checkout could not be found.", status: 404 };
        if (transaction.status === "approved") return { success: true, alreadyCompleted: true };
        if (transaction.status !== "pending") {
            return { error: "This test checkout is no longer pending.", status: 409 };
        }
        const updated = await models.WalletTransaction.updateOne(
            { id: transaction.id, userId: req.session.user.id, status: "pending" },
            { $set: {
                status: "approved", note: "Local test payment completed; no real payment",
                reviewedAt: new Date()
            } },
            { session: dbSession }
        );
        if (updated.modifiedCount !== 1) {
            return { error: "This test checkout was already processed.", status: 409 };
        }
        await models.User.updateOne(
            { id: req.session.user.id },
            { $inc: { balancePaise: transaction.amountPaise } },
            { session: dbSession }
        );
        return { success: true, alreadyCompleted: false };
    });
    if (result.error) return res.status(result.status).json({ success: false, message: result.error });
    res.json({
        success: true,
        alreadyCompleted: result.alreadyCompleted,
        message: result.alreadyCompleted
            ? "This local test payment was already completed."
            : "Local test payment completed. No real payment was made."
    });
}));

app.post("/api/recharge/verify", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    if (!razorpayEnabled) {
        return res.status(400).json({ success: false, message: "No payment gateway is configured on this server." });
    }
    const orderId = typeof req.body.orderId === "string" ? req.body.orderId.trim() : "";
    const paymentId = typeof req.body.paymentId === "string" ? req.body.paymentId.trim() : "";
    const signature = typeof req.body.signature === "string" ? req.body.signature.trim() : "";
    const transactionId = Number.parseInt(req.body.transactionId, 10);
    if (!orderId || !paymentId || !signature || !Number.isSafeInteger(transactionId)) {
        return res.status(400).json({ success: false, message: "Payment verification data is incomplete." });
    }
    if (!verifyRazorpaySignature({ orderId, paymentId, signature })) {
        return res.status(400).json({ success: false, message: "Payment signature is invalid." });
    }
    const result = await withTransaction(async dbSession => {
        const transaction = await models.WalletTransaction.findOne({
            id: transactionId, userId: req.session.user.id, type: "recharge"
        }).session(dbSession).lean();
        if (!transaction) return { error: "Recharge record could not be found.", status: 404 };
        if (transaction.status === "approved") return { alreadyApproved: true };
        if (transaction.status !== "pending" || transaction.reference !== orderId) {
            return { error: "Payment order does not match this recharge record.", status: 409 };
        }
        const update = await models.WalletTransaction.updateOne(
            { id: transactionId, status: "pending", reference: orderId },
            { $set: {
                status: "approved", reference: paymentId,
                note: "Razorpay payment confirmed", reviewedAt: new Date()
            } },
            { session: dbSession }
        );
        if (update.modifiedCount !== 1) {
            return { error: "Payment has already been processed.", status: 409 };
        }
        await models.User.updateOne(
            { id: transaction.userId }, { $inc: { balancePaise: transaction.amountPaise } },
            { session: dbSession }
        );
        return { alreadyApproved: false };
    });
    if (result.error) return res.status(result.status).json({ success: false, message: result.error });
    res.json({
        success: true,
        message: result.alreadyApproved ? "Recharge already confirmed." : "Recharge completed successfully."
    });
}));

app.post("/api/recharge/watchpays/callback", asyncRoute(async (req, res) => {
    if (!watchPaysEnabled) return res.status(503).type("text").send("WatchPays is not configured.");
    const merchantOrderNo = typeof req.body.merchantOrder === "string"
        ? req.body.merchantOrder.trim() : "";
    const gatewayOrderNo = typeof req.body.orderNo === "string"
        ? req.body.orderNo.trim().slice(0, 120) : "";
    const reportedStatus = typeof req.body.status === "string"
        ? req.body.status.trim().slice(0, 40).toLowerCase() : "";
    const callbackAmountPaise = parseRupees(req.body.amount);
    if (!merchantOrderNo || merchantOrderNo.length > 100 || !gatewayOrderNo
        || !["success", "failed", "pending"].includes(reportedStatus)
        || callbackAmountPaise === null || callbackAmountPaise <= 0) {
        return res.status(400).type("text").send("Invalid callback.");
    }
    const transaction = await models.WalletTransaction.findOne({
        type: "recharge", reference: merchantOrderNo
    }).lean();
    if (!transaction || !merchantOrderNo.startsWith("watchpays-")) {
        return res.status(404).type("text").send("Recharge order not found.");
    }
    if (transaction.amountPaise !== callbackAmountPaise) {
        return res.status(400).type("text").send("Recharge amount does not match.");
    }
    if (transaction.status === "pending") {
        const note = reportedStatus === "success"
            ? `WatchPays callback reports payment success (gateway order ${gatewayOrderNo}); verify in provider dashboard before approval.`
            : `WatchPays callback reports status '${reportedStatus}' (gateway order ${gatewayOrderNo}); admin review required.`;
        await models.WalletTransaction.updateOne(
            { id: transaction.id, status: "pending" }, { $set: { note } }
        );
    }
    res.type("text").send("success");
}));

app.post("/api/withdrawal", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    const hasPurchasedVip4 = await models.UserProduct.exists({
        userId: req.session.user.id, productId: withdrawalUnlockProductId
    });
    if (!hasPurchasedVip4) {
        return res.status(403).json({
            success: false,
            message: "Purchase VIP 4 before requesting a withdrawal. A ₹295 deposit alone does not unlock withdrawals."
        });
    }
    const amountPaise = parseRupees(req.body.amount);
    const minimum = Number(await settingValue("minimum_withdrawal_rupees", "170"));
    if (!amountPaise || amountPaise < minimum * 100) {
        return res.status(400).json({ success: false, message: "Enter a valid withdrawal amount." });
    }
    if (!await models.BankAccount.exists({ userId: req.session.user.id })) {
        return res.status(400).json({
            success: false,
            message: "Save your bank account in Bank setup before requesting a withdrawal."
        });
    }
    const payoutReference = `withdrawal-${Date.now()}-${randomBytes(16).toString("hex")}`;
    const result = await withTransaction(async dbSession => {
        const user = await models.User.findOneAndUpdate({
            id: req.session.user.id,
            $expr: { $gte: ["$balancePaise", { $add: ["$reservedWithdrawalPaise", amountPaise] }] }
        }, { $inc: { reservedWithdrawalPaise: amountPaise } }, { new: true, session: dbSession });
        if (!user) return { error: "Amount exceeds your available balance." };
        const transactionId = await nextId("wallet_transactions", dbSession);
        await models.WalletTransaction.create([{
            id: transactionId, userId: req.session.user.id, type: "withdrawal",
            amountPaise, status: "pending", reference: payoutReference,
            note: "Awaiting payout review"
        }], { session: dbSession });
        return {
            transactionId,
            availableBalancePaise: Math.max(0, user.balancePaise - user.reservedWithdrawalPaise)
        };
    });
    if (result.error) return res.status(400).json({ success: false, message: result.error });
    res.status(202).json({
        success: true,
        transactionId: result.transactionId,
        availableBalancePaise: result.availableBalancePaise,
        message: "Withdrawal submitted successfully."
    });
}));

app.get("/api/spin", requireAuth, asyncRoute(async (req, res) => {
    const userId = req.session.user.id;
    const [spinsAvailable, user, history] = await Promise.all([
        models.UserProduct.countDocuments({ userId, spinUsedAt: null }),
        models.User.findOne({ id: userId }).select("balancePaise reservedWithdrawalPaise").lean(),
        models.UserProduct.find({ userId, spinUsedAt: { $ne: null } })
            .sort({ spinUsedAt: -1 }).limit(30).select("spinResultCode spinUsedAt").lean()
    ]);
    res.set("Cache-Control", "no-store");
    res.json({
        success: true,
        spinsAvailable,
        balancePaise: Math.max(0, user.balancePaise - user.reservedWithdrawalPaise),
        history: history.map(item => {
            const prize = spinPrizes.find(candidate => candidate.code === item.spinResultCode);
            return prize ? {
                type: prize.type,
                label: prize.label,
                value: prize.value,
                createdAt: item.spinUsedAt
            } : null;
        }).filter(Boolean)
    });
}));

app.post("/api/spin", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    const result = await withTransaction(async dbSession => {
        const roll = randomInt(totalSpinPrizeWeight);
        let weight = 0;
        const prize = spinPrizes.find(candidate => {
            weight += candidate.weight;
            return roll < weight;
        });
        const usedAt = new Date();
        const productPurchase = await models.UserProduct.findOneAndUpdate(
            { userId: req.session.user.id, spinUsedAt: null },
            { $set: { spinUsedAt: usedAt, spinResultCode: prize.code } },
            { sort: { id: 1 }, new: false, session: dbSession }
        ).lean();
        if (!productPurchase) return { error: "Buy a plan first to get one spin per purchase.", status: 409 };

        let user;
        if (prize.amountPaise > 0) {
            user = await models.User.findOneAndUpdate(
                { id: req.session.user.id },
                { $inc: { balancePaise: prize.amountPaise } },
                { new: true, session: dbSession }
            ).select("balancePaise").lean();
            if (!user) return { error: "Your account could not be found.", status: 404 };
            await models.WalletTransaction.create([{
                id: await nextId("wallet_transactions", dbSession),
                userId: req.session.user.id,
                type: "adjustment",
                amountPaise: prize.amountPaise,
                status: "approved",
                reference: `spin-${productPurchase.id}`,
                note: `Spin reward for plan purchase #${productPurchase.id}: ${prize.label}`,
                reviewedAt: usedAt
            }], { session: dbSession });
        } else {
            user = await models.User.findOne({ id: req.session.user.id })
                .select("balancePaise").session(dbSession).lean();
            if (!user) return { error: "Your account could not be found.", status: 404 };
        }
        const spinsAvailable = await models.UserProduct.countDocuments({
            userId: req.session.user.id,
            spinUsedAt: null
        }).session(dbSession);
        return {
            prize: {
                type: prize.type,
                label: prize.label,
                value: prize.value,
                wheelIndex: prize.wheelIndices[randomInt(prize.wheelIndices.length)]
            },
            balancePaise: user.balancePaise,
            spinsAvailable
        };
    });
    if (result.error) return res.status(result.status).json({ success: false, message: result.error });
    res.json({ success: true, ...result });
}));

app.get("/api/products", requireAuth, asyncRoute(async (req, res) => {
    const products = await models.Product.find({ active: true }).sort({ category: 1, id: 1 }).lean();
    const counts = await models.UserProduct.aggregate([
        { $match: { userId: req.session.user.id } },
        { $group: { _id: "$productId", count: { $sum: 1 } } }
    ]);
    const purchasedCounts = new Map(counts.map(row => [row._id, row.count]));
    res.set("Cache-Control", "no-store");
    res.json({
        success: true,
        products: products.map(product => ({
            id: product.id, name: product.name, category: product.category,
            pricePaise: product.pricePaise, durationDays: product.durationDays,
            dailyRewardPaise: product.dailyRewardPaise, totalRewardPaise: product.totalRewardPaise,
            purchaseLimit: product.purchaseLimit, imageUrl: product.imageUrl,
            purchasedCount: purchasedCounts.get(product.id) || 0
        }))
    });
}));

app.get("/api/wallet", requireAuth, asyncRoute(async (req, res) => {
    const userId = req.session.user.id;
    const [user, transactions, bankAccount, withdrawalValue, approvedRecharges, approvedRewards, hasPurchasedVip4] =
        await Promise.all([
            models.User.findOne({ id: userId }).select("balancePaise reservedWithdrawalPaise").lean(),
            models.WalletTransaction.find({ userId }).sort({ id: -1 }).limit(100).lean(),
            models.BankAccount.findOne({ userId }).select("accountLast4 ifsc").lean(),
            settingValue("minimum_withdrawal_rupees", "170"),
            models.WalletTransaction.aggregate([
                { $match: { userId, type: "recharge", status: "approved" } },
                { $group: { _id: null, total: { $sum: "$amountPaise" } } }
            ]),
            models.WalletTransaction.aggregate([
                { $match: { userId, type: "adjustment", status: "approved", amountPaise: { $gt: 0 } } },
                { $group: { _id: null, total: { $sum: "$amountPaise" } } }
            ]),
            models.UserProduct.exists({ userId, productId: withdrawalUnlockProductId })
        ]);
    const [productRequests, claims] = await Promise.all([
        models.ProductRequest.find({ userId }).lean(),
        models.MissionClaim.find({ userId }).lean()
    ]);
    const missionIds = [...new Set(claims.map(claim => claim.missionId))];
    const missions = await models.Mission.find({ id: { $in: missionIds } })
        .select("id name rewardPaise").lean();
    const missionNames = new Map(missions.map(mission => [mission.id, mission.name]));
    const requests = [
        ...productRequests.map(item => ({
            id: item.id, type: "product", title: item.productName, amountPaise: item.pricePaise,
            status: item.status, note: item.note, createdAt: item.createdAt
        })),
        ...claims.map(item => ({
            id: item.id, type: "mission", title: missionNames.get(item.missionId) || "",
            amountPaise: (missions.find(mission => mission.id === item.missionId) || {}).rewardPaise || 0,
            status: item.status, note: item.note, createdAt: item.createdAt
        }))
    ].sort((left, right) => new Date(right.createdAt) - new Date(left.createdAt));
    res.set("Cache-Control", "no-store");
    res.json({
        success: true,
        balancePaise: user ? user.balancePaise : 0,
        pendingWithdrawalsPaise: user ? user.reservedWithdrawalPaise : 0,
        availableBalancePaise: user
            ? Math.max(0, user.balancePaise - user.reservedWithdrawalPaise)
            : 0,
        approvedRechargesPaise: approvedRecharges[0]?.total || 0,
        approvedRewardsPaise: approvedRewards[0]?.total || 0,
        bankAccount: bankAccount || null,
        minimumWithdrawal: Number(withdrawalValue),
        hasPurchasedVip4: Boolean(hasPurchasedVip4),
        transactions: transactions.map(item => ({
            id: item.id, type: item.type, amountPaise: item.amountPaise, status: item.status,
            reference: item.reference, note: item.note, createdAt: item.createdAt, reviewedAt: item.reviewedAt
        })),
        requests
    });
}));

app.get("/api/team", requireAuth, asyncRoute(async (req, res) => {
    const userId = req.session.user.id;
    const descendants = await descendantsOf(userId, 3);
    const userIds = descendants.map(item => item.user.id);
    const recharges = await models.WalletTransaction.aggregate([
        { $match: { userId: { $in: userIds }, status: "approved", type: "recharge" } },
        { $group: { _id: "$userId", total: { $sum: "$amountPaise" } } }
    ]);
    const rechargeMap = new Map(recharges.map(row => [row._id, row.total]));
    const levels = [1, 2, 3].map(level => {
        const members = descendants.filter(item => item.level === level);
        return {
            level, total: members.length,
            active: members.filter(item => item.user.status === "active").length,
            rechargePaise: members.reduce((total, item) => total + (rechargeMap.get(item.user.id) || 0), 0)
        };
    });
    const profile = await models.User.findOne({ id: userId }).select("referralCode").lean();
    res.set("Cache-Control", "no-store");
    res.json({
        success: true, referralCode: profile.referralCode,
        totalMembers: levels.reduce((sum, row) => sum + row.total, 0),
        activeMembers: levels.reduce((sum, row) => sum + row.active, 0),
        totalRechargePaise: levels.reduce((sum, row) => sum + row.rechargePaise, 0),
        levels, commissionPaise: 0
    });
}));

app.get("/api/missions", requireAuth, asyncRoute(async (req, res) => {
    const [activeMembers, missions, claims] = await Promise.all([
        countActiveTeamMembers(req.session.user.id),
        models.Mission.find({ active: true }).sort({ targetMembers: 1, id: 1 }).lean(),
        models.MissionClaim.find({ userId: req.session.user.id }).select("missionId status").lean()
    ]);
    const claimStatus = new Map(claims.map(claim => [claim.missionId, claim.status]));
    res.json({
        success: true, activeMembers,
        missions: missions.map(mission => ({
            id: mission.id, name: mission.name, description: mission.description,
            targetMembers: mission.targetMembers, rewardPaise: mission.rewardPaise,
            claimStatus: claimStatus.get(mission.id) || null
        }))
    });
}));

app.post("/api/missions/claim", requireCsrf, requireAuth, asyncRoute(async (req, res) => {
    const missionId = Number.parseInt(req.body.missionId, 10);
    if (!Number.isSafeInteger(missionId) || missionId < 1) {
        return res.status(400).json({ success: false, message: "Choose a valid mission." });
    }
    const mission = await models.Mission.findOne({ id: missionId, active: true })
        .select("id targetMembers").lean();
    if (!mission) return res.status(404).json({ success: false, message: "Mission not found." });
    if (await countActiveTeamMembers(req.session.user.id) < mission.targetMembers) {
        return res.status(400).json({
            success: false,
            message: "Your verified team has not reached this mission yet."
        });
    }
    const existing = await models.MissionClaim.findOne({
        userId: req.session.user.id, missionId
    }).lean();
    if (existing && existing.status !== "rejected") {
        return res.status(409).json({
            success: false,
            message: existing.status === "approved"
                ? "This mission reward was already approved."
                : "This mission is already waiting for review."
        });
    }
    if (existing) {
        await models.MissionClaim.updateOne(
            { id: existing.id, status: "rejected" },
            { $set: {
                status: "pending", note: "", reviewedByAdminId: null,
                createdAt: new Date(), reviewedAt: null
            } }
        );
    } else {
        await models.MissionClaim.create({
            id: await nextId("mission_claims"),
            userId: req.session.user.id,
            missionId,
            status: "pending"
        });
    }
    res.status(202).json({ success: true, message: "Mission claim submitted for admin verification." });
}));

app.get("/api/admin/session", asyncRoute(async (req, res) => {
    res.set("Cache-Control", "no-store");
    if (!req.session.admin || req.session.impersonation) {
        return res.status(401).json({
            success: false, configured: (await models.Admin.countDocuments()) > 0
        });
    }
    const admin = await models.Admin.findOne({ id: req.session.admin.id })
        .select("username displayUsername passwordChangeRequired credentialVersion").lean();
    if (!admin || !credentialVersionMatches(req.session.admin, admin)) {
        await destroySession(req, res);
        return res.status(401).json({ success: false });
    }
    const username = admin.displayUsername || admin.username;
    res.json({
        success: true,
        admin: { username, passwordChangeRequired: admin.passwordChangeRequired },
        csrfToken: req.session.csrfToken
    });
}));

app.post("/api/admin/login", adminLimiter, requireCsrf, asyncRoute(async (req, res) => {
    const username = typeof req.body.username === "string" ? req.body.username.trim() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const admin = await models.Admin.findOne({ username: username.toLowerCase() })
        .collation({ locale: "en", strength: 2 }).lean();
    const passwordMatches = admin
        ? await bcrypt.compare(password, admin.passwordHash)
        : await bcrypt.compare(password, dummyPasswordHash);
    if (!admin || !passwordMatches || !password) {
        return res.status(401).json({ success: false, message: "Invalid admin username or password." });
    }
    const adminName = admin.displayUsername || admin.username;
    await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
    req.session.admin = {
        id: admin.id, username: adminName, credentialVersion: admin.credentialVersion || 0
    };
    req.session.csrfToken = createCsrfToken();
    await new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
    await models.Admin.updateOne({ id: admin.id }, { $set: { lastLoginAt: new Date() } });
    await auditAdmin(admin.id, "login", "admin", admin.id, {});
    res.json({
        success: true,
        admin: {
            username: adminName,
            passwordChangeRequired: Boolean(admin.passwordChangeRequired)
        },
        csrfToken: req.session.csrfToken
    });
}));

app.post("/api/admin/logout", requireCsrf, requireAdmin, asyncRoute(async (req, res) => {
    if (req.session.impersonation) {
        return res.status(403).json({ success: false, message: "Return to admin before signing out." });
    }
    await auditAdmin(req.session.admin.id, "logout", "admin", req.session.admin.id, {});
    await new Promise((resolve, reject) => req.session.destroy(error => error ? reject(error) : resolve()));
    res.clearCookie("kingfisher.sid", {
        httpOnly: true, secure: isProduction, sameSite: "strict"
    });
    res.json({ success: true });
}));

app.post("/api/admin/impersonation/stop", requireCsrf, requireAdmin, asyncRoute(async (req, res) => {
    const impersonation = req.session.impersonation;
    if (!impersonation) {
        return res.status(409).json({ success: false, message: "No user support session is active." });
    }
    await auditAdmin(req.session.admin.id, "stop_user_support_access", "user", impersonation.userId, {
        startedAt: impersonation.startedAt
    });
    delete req.session.user;
    delete req.session.impersonation;
    req.session.csrfToken = createCsrfToken();
    await new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
    res.json({ success: true, message: "Returned to admin panel." });
}));

app.post("/api/admin/change-password", requireCsrf, requireAdmin, asyncRoute(async (req, res) => {
    const currentPassword = typeof req.body.currentPassword === "string" ? req.body.currentPassword : "";
    const newPassword = typeof req.body.newPassword === "string" ? req.body.newPassword : "";
    const admin = await models.Admin.findOne({ id: req.session.admin.id }).select("passwordHash").lean();
    if (!admin || !(await bcrypt.compare(currentPassword, admin.passwordHash))) {
        return res.status(400).json({ success: false, message: "Current password is incorrect." });
    }
    if (newPassword.length < 12 || newPassword.length > 128) {
        return res.status(400).json({ success: false, message: "New password must be 12 to 128 characters." });
    }
    const passwordHash = await bcrypt.hash(newPassword, 12);
    const result = await withTransaction(async dbSession => {
        const updatedAdmin = await models.Admin.findOneAndUpdate(
            { id: req.session.admin.id, passwordHash: admin.passwordHash },
            { $set: { passwordHash, passwordChangeRequired: false }, $inc: { credentialVersion: 1 } },
            { new: true, session: dbSession }
        ).select("id username displayUsername credentialVersion").lean();
        if (!updatedAdmin) {
            return { error: "The password changed in another session. Please sign in again.", status: 409 };
        }
        await models.Session.deleteMany({ "data.admin.id": updatedAdmin.id }, { session: dbSession });
        return updatedAdmin;
    });
    if (result.error) return res.status(result.status).json({ success: false, message: result.error });
    const adminName = result.displayUsername || result.username;
    await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
    req.session.admin = {
        id: result.id, username: adminName, credentialVersion: result.credentialVersion
    };
    req.session.csrfToken = createCsrfToken();
    await new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
    await auditAdmin(req.session.admin.id, "change_password", "admin", req.session.admin.id, {});
    res.json({ success: true, message: "Admin password updated.", csrfToken: req.session.csrfToken });
}));

app.use("/api/admin", (req, res, next) => {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
    requireCsrf(req, res, next);
}, requireAdmin, (req, res, next) => {
    if (req.adminAccount.passwordChangeRequired) {
        return res.status(403).json({
            success: false,
            message: "Change the initial admin password before using the admin panel."
        });
    }
    if (req.session.impersonation) {
        return res.status(403).json({
            success: false,
            message: "Admin actions are unavailable during user support access."
        });
    }
    next();
});

app.post("/api/admin/media/:kind", express.raw({
    type: ["image/png", "image/jpeg", "image/webp"], limit: "3mb"
}), asyncRoute(async (req, res) => {
    const kind = req.params.kind;
    const mimeTypes = {
        "image/png": {
            extension: "png",
            signature: buffer => buffer.length >= 8
                && buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
        },
        "image/jpeg": {
            extension: "jpg",
            signature: buffer => buffer.length >= 3 && buffer[0] === 255 && buffer[1] === 216 && buffer[2] === 255
        },
        "image/webp": {
            extension: "webp",
            signature: buffer => buffer.length >= 12
                && buffer.toString("ascii", 0, 4) === "RIFF"
                && buffer.toString("ascii", 8, 12) === "WEBP"
        }
    };
    const mediaType = mimeTypes[req.get("Content-Type")];
    const image = req.body;
    if (!["logo", "banner", "invite-banner", "spinner", "product"].includes(kind)) {
        return res.status(400).json({ success: false, message: "Choose a valid image type." });
    }
    if (!Buffer.isBuffer(image) || image.length === 0 || !mediaType || !mediaType.signature(image)) {
        return res.status(400).json({ success: false, message: "Upload a valid PNG, JPEG, or WebP image." });
    }
    const filename = `${randomBytes(16).toString("hex")}.${mediaType.extension}`;
    const imageUrl = `/uploads/media/${filename}`;
    try {
        fs.writeFileSync(path.join(mediaDirectory, filename), image, { flag: "wx", mode: 0o644 });
        if (kind !== "product") {
            const settingKey = kind === "invite-banner" ? "invite_banner_url" : `site_${kind}_url`;
            await models.SiteSetting.updateOne(
                { key: settingKey },
                { $set: { key: settingKey, value: imageUrl, updatedByAdminId: req.session.admin.id } },
                { upsert: true }
            );
            await auditAdmin(req.session.admin.id, `update_${kind}_image`, "setting", settingKey, { imageUrl });
        } else {
            await auditAdmin(req.session.admin.id, "upload_product_image", "media", filename, {});
        }
    } catch (error) {
        console.error("Admin media upload failed:", error);
        return res.status(500).json({ success: false, message: "Could not save the image. Please try again." });
    }
    res.status(201).json({ success: true, imageUrl });
}));

app.get("/api/admin/overview", asyncRoute(async (req, res) => {
    const [
        users, activeUsers, suspendedUsers, walletSummary, pendingTransactions,
        pendingMissionClaims, pendingProductRequests, activeProducts, activeMissions
    ] = await Promise.all([
        models.User.countDocuments(),
        models.User.countDocuments({ status: "active" }),
        models.User.countDocuments({ status: "suspended" }),
        models.User.aggregate([{ $group: { _id: null, total: { $sum: "$balancePaise" } } }]),
        models.WalletTransaction.countDocuments({ status: { $in: ["pending", "processing"] } }),
        models.MissionClaim.countDocuments({ status: "pending" }),
        models.ProductRequest.countDocuments({ status: "pending" }),
        models.Product.countDocuments({ active: true }),
        models.Mission.countDocuments({ active: true })
    ]);
    res.json({
        success: true,
        summary: {
            users, activeUsers, suspendedUsers, walletPaise: walletSummary[0]?.total || 0,
            pendingTransactions, pendingMissionClaims, pendingProductRequests, activeProducts, activeMissions
        }
    });
}));

app.get("/api/admin/users", asyncRoute(async (req, res) => {
    const search = typeof req.query.search === "string" ? req.query.search.trim().slice(0, 80) : "";
    const page = Math.max(1, Math.min(10000, Number.parseInt(req.query.page, 10) || 1));
    const limit = 25;
    const escapedSearch = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const filter = search
        ? { $or: [{ name: { $regex: escapedSearch, $options: "i" } }, { phone: { $regex: escapedSearch } }] }
        : {};
    const [rows, total] = await Promise.all([
        models.User.find(filter).select("id name phone status balancePaise createdAt")
            .sort({ id: -1 }).skip((page - 1) * limit).limit(limit).lean(),
        models.User.countDocuments(filter)
    ]);
    const bankIds = await models.BankAccount.distinct("userId", { userId: { $in: rows.map(user => user.id) } });
    const bankSet = new Set(bankIds);
    res.json({
        success: true,
        users: rows.map(user => ({
            id: user.id, name: user.name, phone: user.phone, status: user.status,
            balancePaise: Math.max(0, user.balancePaise - user.reservedWithdrawalPaise), createdAt: user.createdAt,
            bankConfigured: bankSet.has(user.id)
        })),
        total, page, pageSize: limit
    });
}));

app.get("/api/admin/demo-accounts", asyncRoute(async (req, res) => {
    const [accounts, rows] = await Promise.all([
        models.DemoAccount.find().sort({ id: -1 }).limit(200).lean(),
        models.DemoWalletTransaction.find().sort({ id: -1 }).limit(200).lean()
    ]);
    const accountIds = [...new Set(rows.map(item => item.demoAccountId))];
    const accountRows = await models.DemoAccount.find({ id: { $in: accountIds } })
        .select("id demoCode name").lean();
    const accountMap = new Map(accountRows.map(item => [item.id, item]));
    res.set("Cache-Control", "no-store");
    res.json({
        success: true,
        accounts: accounts.map(item => ({
            id: item.id, demoCode: item.demoCode, name: item.name,
            balancePaise: item.balancePaise, createdAt: item.createdAt
        })),
        transactions: rows.map(item => {
            const account = accountMap.get(item.demoAccountId) || {};
            return {
                id: item.id, demoAccountId: item.demoAccountId, demoCode: account.demoCode || "",
                accountName: account.name || "", type: item.type, amountPaise: item.amountPaise,
                note: item.note, createdAt: item.createdAt
            };
        })
    });
}));

app.post("/api/admin/demo-accounts", asyncRoute(async (req, res) => {
    const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
    if (!name || name.length > 80) {
        return res.status(400).json({
            success: false, message: "Enter a demo account name up to 80 characters."
        });
    }
    const demoCode = `DEMO-${randomBytes(4).toString("hex").toUpperCase()}`;
    const id = await nextId("demo_accounts");
    await models.DemoAccount.create({ id, demoCode, name, createdByAdminId: req.session.admin.id });
    await auditAdmin(req.session.admin.id, "create_demo_account", "demo_account", id, { demoCode, name });
    res.status(201).json({
        success: true,
        account: { id, demoCode, name, balancePaise: 0 },
        message: "Demo account created. It is separate from real users and cannot receive or send real money."
    });
}));

app.post("/api/admin/demo-accounts/:id/transactions", asyncRoute(async (req, res) => {
    const accountId = /^\d+$/.test(req.params.id) ? Number(req.params.id) : NaN;
    const type = req.body.type;
    const amountPaise = parseRupees(req.body.amount);
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!Number.isSafeInteger(accountId) || accountId < 1 || !["deposit", "withdrawal"].includes(type)
        || !Number.isSafeInteger(amountPaise) || amountPaise <= 0 || !note) {
        return res.status(400).json({
            success: false, message: "Enter a valid demo account, transaction type, amount and note."
        });
    }
    const result = await withTransaction(async dbSession => {
        const account = await models.DemoAccount.findOne({ id: accountId }).session(dbSession).lean();
        if (!account) return { error: "Demo account not found.", status: 404 };
        if (type === "withdrawal" && account.balancePaise < amountPaise) {
            return { error: "Demo withdrawal exceeds the demo balance.", status: 400 };
        }
        const adjustment = type === "deposit" ? amountPaise : -amountPaise;
        const updated = await models.DemoAccount.updateOne(
            { id: accountId, ...(adjustment < 0 ? { balancePaise: { $gte: -adjustment } } : {}) },
            { $inc: { balancePaise: adjustment } }, { session: dbSession }
        );
        if (updated.modifiedCount !== 1) {
            return { error: "Demo withdrawal exceeds the demo balance.", status: 400 };
        }
        const balancePaise = account.balancePaise + adjustment;
        const transactionId = await nextId("demo_wallet_transactions", dbSession);
        await models.DemoWalletTransaction.create([{
            id: transactionId, demoAccountId: accountId,
            type: type === "deposit" ? "demo_deposit" : "demo_withdrawal",
            amountPaise, note, createdByAdminId: req.session.admin.id
        }], { session: dbSession });
        await auditAdmin(req.session.admin.id, `demo_${type}`, "demo_account", accountId, {
            demoCode: account.demoCode, amountPaise, balancePaise, note
        }, dbSession);
        return { balancePaise, transactionId };
    });
    if (result.error) return res.status(result.status).json({ success: false, message: result.error });
    res.status(201).json({
        success: true, ...result,
        message: `Simulated demo ${type} recorded. No real wallet or payment was changed.`
    });
}));

app.patch("/api/admin/users/:id/status", asyncRoute(async (req, res) => {
    const userId = Number.parseInt(req.params.id, 10);
    const status = req.body.status;
    if (!Number.isSafeInteger(userId) || !["active", "suspended"].includes(status)) {
        return res.status(400).json({ success: false, message: "Invalid user status." });
    }
    const result = await models.User.updateOne({ id: userId }, { $set: { status } });
    if (!result.matchedCount) return res.status(404).json({ success: false, message: "User not found." });
    await auditAdmin(req.session.admin.id, "set_user_status", "user", userId, { status });
    res.json({ success: true });
}));

app.post("/api/admin/users/:id/impersonate", asyncRoute(async (req, res) => {
    const userId = Number.parseInt(req.params.id, 10);
    const target = await models.User.findOne({ id: userId })
        .select("id name status credentialVersion").lean();
    if (!Number.isSafeInteger(userId) || !target) {
        return res.status(404).json({ success: false, message: "User not found." });
    }
    if (target.status !== "active") {
        return res.status(409).json({
            success: false, message: "Activate this account before starting support access."
        });
    }
    const admin = req.session.admin;
    if (!admin || req.session.impersonation) {
        return res.status(403).json({ success: false, message: "Admin support access is unavailable." });
    }
    await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
    const startedAt = new Date().toISOString();
    req.session.admin = admin;
    req.session.user = {
        id: target.id, name: target.name, credentialVersion: target.credentialVersion || 0
    };
    req.session.impersonation = { userId: target.id, startedAt };
    req.session.csrfToken = createCsrfToken();
    await auditAdmin(admin.id, "start_user_support_access", "user", target.id, { startedAt });
    await new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
    res.json({ success: true, destination: "/home.html" });
}));

app.delete("/api/admin/users/:id/bank-account", asyncRoute(async (req, res) => {
    const userId = Number.parseInt(req.params.id, 10);
    if (!Number.isSafeInteger(userId) || userId < 1) {
        return res.status(400).json({ success: false, message: "Invalid user." });
    }
    if (await models.WalletTransaction.exists({
        userId, type: "withdrawal", status: { $in: ["pending", "processing"] }
    })) {
        return res.status(409).json({
            success: false, message: "Bank details cannot be removed while a withdrawal is pending."
        });
    }
    const result = await models.BankAccount.deleteOne({ userId });
    if (!result.deletedCount) {
        return res.status(404).json({ success: false, message: "This user has no saved bank account." });
    }
    await auditAdmin(req.session.admin.id, "remove_user_bank_account", "user", userId, {});
    res.json({ success: true, message: "Saved bank details removed." });
}));

app.post("/api/admin/users/:id/reset-password", asyncRoute(async (req, res) => {
    const userId = Number.parseInt(req.params.id, 10);
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (!Number.isSafeInteger(userId) || password.length < 8 || password.length > 128) {
        return res.status(400).json({
            success: false, message: "User password must be 8 to 128 characters."
        });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await withTransaction(async dbSession => {
        const updatedUser = await models.User.updateOne(
            { id: userId },
            { $set: { passwordHash }, $inc: { credentialVersion: 1 } },
            { session: dbSession }
        );
        if (!updatedUser.matchedCount) return { error: "User not found.", status: 404 };
        await models.Session.deleteMany({ "data.user.id": userId }, { session: dbSession });
        return { success: true };
    });
    if (result.error) return res.status(result.status).json({ success: false, message: result.error });
    await auditAdmin(req.session.admin.id, "reset_user_password", "user", userId, {});
    res.json({
        success: true, message: "User password reset. Share the temporary password securely."
    });
}));

app.post("/api/admin/users/:id/adjust-balance", asyncRoute(async (req, res) => {
    const userId = Number.parseInt(req.params.id, 10);
    const amountPaise = parseRupees(req.body.amount);
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!Number.isSafeInteger(userId) || !amountPaise || !note) {
        return res.status(400).json({
            success: false, message: "Enter a valid non-zero amount and reason."
        });
    }
    const result = await withTransaction(async dbSession => {
        const user = await models.User.findOneAndUpdate({
            id: userId,
            ...(amountPaise < 0 ? { balancePaise: { $gte: -amountPaise } } : {})
        }, { $inc: { balancePaise: amountPaise } }, { new: true, session: dbSession });
        if (!user) {
            const exists = await models.User.exists({ id: userId }).session(dbSession);
            return exists
                ? { error: "Adjustment would make the wallet negative.", status: 400 }
                : { error: "User not found.", status: 404 };
        }
        await models.WalletTransaction.create([{
            id: await nextId("wallet_transactions", dbSession),
            userId, type: "adjustment", amountPaise, status: "approved", note,
            createdByAdminId: req.session.admin.id,
            reviewedByAdminId: req.session.admin.id, reviewedAt: new Date()
        }], { session: dbSession });
        await auditAdmin(req.session.admin.id, "adjust_wallet", "user", userId, {
            amountPaise, note
        }, dbSession);
        return { balancePaise: user.balancePaise };
    });
    if (result.error) return res.status(result.status).json({ success: false, message: result.error });
    res.json({ success: true, balancePaise: result.balancePaise });
}));

app.get("/api/admin/products", asyncRoute(async (req, res) => {
    const products = await models.Product.find().sort({ category: 1, id: 1 }).lean();
    res.json({
        success: true,
        products: products.map(product => ({
            id: product.id, name: product.name, category: product.category,
            pricePaise: product.pricePaise, durationDays: product.durationDays,
            dailyRewardPaise: product.dailyRewardPaise, totalRewardPaise: product.totalRewardPaise,
            purchaseLimit: product.purchaseLimit, active: product.active ? 1 : 0, imageUrl: product.imageUrl
        }))
    });
}));

function productValues(body) {
    const name = typeof body.name === "string" ? body.name.trim().slice(0, 80) : "";
    const category = body.category;
    const pricePaise = parseRupees(body.price);
    const durationDays = Number(body.durationDays);
    const dailyRewardPaise = parseRupees(body.dailyReward || 0);
    const totalRewardPaise = parseRupees(body.totalReward || 0);
    const purchaseLimit = Number(body.purchaseLimit);
    const imageUrl = typeof body.imageUrl === "string" ? body.imageUrl.trim() : "";
    if (!name || !["daily", "vip"].includes(category)
        || pricePaise === null || pricePaise < 0
        || !Number.isInteger(durationDays) || durationDays < 1 || durationDays > 3650
        || dailyRewardPaise === null || dailyRewardPaise < 0
        || totalRewardPaise === null || totalRewardPaise < 0
        || !Number.isInteger(purchaseLimit) || purchaseLimit < 1 || purchaseLimit > 10000
        || (imageUrl && !/^\/(?:uploads\/media\/[a-f0-9]{32}\.(?:png|jpg|webp)|assets\/images\/[a-zA-Z0-9_-]+\.(?:svg|png|jpe?g|webp))$/.test(imageUrl))) {
        return null;
    }
    return { name, category, pricePaise, durationDays, dailyRewardPaise, totalRewardPaise, purchaseLimit, imageUrl };
}

app.post("/api/admin/products", asyncRoute(async (req, res) => {
    const values = productValues(req.body);
    if (!values) {
        return res.status(400).json({ success: false, message: "Check product fields and try again." });
    }
    const id = await nextId("products");
    await models.Product.create({ id, ...values });
    await auditAdmin(req.session.admin.id, "create_product", "product", id, { name: values.name });
    res.status(201).json({ success: true, id });
}));

app.put("/api/admin/products/:id", asyncRoute(async (req, res) => {
    const productId = Number.parseInt(req.params.id, 10);
    const values = productValues(req.body);
    const active = req.body.active === false || req.body.active === 0 ? false : true;
    if (!Number.isSafeInteger(productId) || !values) {
        return res.status(400).json({ success: false, message: "Check product fields and try again." });
    }
    const result = await models.Product.updateOne({ id: productId }, { $set: { ...values, active } });
    if (!result.matchedCount) return res.status(404).json({ success: false, message: "Product not found." });
    await auditAdmin(req.session.admin.id, "update_product", "product", productId, { name: values.name, active });
    res.json({ success: true });
}));

app.delete("/api/admin/products/:id", asyncRoute(async (req, res) => {
    const productId = Number.parseInt(req.params.id, 10);
    const result = await models.Product.updateOne({ id: productId }, { $set: { active: false } });
    if (!result.matchedCount) return res.status(404).json({ success: false, message: "Product not found." });
    await auditAdmin(req.session.admin.id, "deactivate_product", "product", productId, {});
    res.json({ success: true });
}));

app.get("/api/admin/missions", asyncRoute(async (req, res) => {
    const missions = await models.Mission.find().sort({ targetMembers: 1, id: 1 }).lean();
    res.json({
        success: true,
        missions: missions.map(mission => ({
            id: mission.id, name: mission.name, description: mission.description,
            targetMembers: mission.targetMembers, rewardPaise: mission.rewardPaise,
            active: mission.active ? 1 : 0
        }))
    });
}));

function missionValues(body) {
    const name = typeof body.name === "string" ? body.name.trim().slice(0, 100) : "";
    const description = typeof body.description === "string" ? body.description.trim().slice(0, 500) : "";
    const targetMembers = Number(body.targetMembers);
    const rewardPaise = parseRupees(body.reward);
    if (!name || !Number.isInteger(targetMembers) || targetMembers < 0 || targetMembers > 100000000
        || rewardPaise === null || rewardPaise < 0) return null;
    return { name, description, targetMembers, rewardPaise };
}

app.post("/api/admin/missions", asyncRoute(async (req, res) => {
    const values = missionValues(req.body);
    if (!values) {
        return res.status(400).json({ success: false, message: "Check mission fields and try again." });
    }
    const id = await nextId("missions");
    await models.Mission.create({ id, ...values });
    await auditAdmin(req.session.admin.id, "create_mission", "mission", id, { name: values.name });
    res.status(201).json({ success: true, id });
}));

app.put("/api/admin/missions/:id", asyncRoute(async (req, res) => {
    const missionId = Number.parseInt(req.params.id, 10);
    const values = missionValues(req.body);
    const active = req.body.active === false || req.body.active === 0 ? false : true;
    if (!Number.isSafeInteger(missionId) || !values) {
        return res.status(400).json({ success: false, message: "Check mission fields and try again." });
    }
    const result = await models.Mission.updateOne({ id: missionId }, { $set: { ...values, active } });
    if (!result.matchedCount) return res.status(404).json({ success: false, message: "Mission not found." });
    await auditAdmin(req.session.admin.id, "update_mission", "mission", missionId, { name: values.name, active });
    res.json({ success: true });
}));

app.get("/api/admin/transactions", asyncRoute(async (req, res) => {
    const status = typeof req.query.status === "string" ? req.query.status : "";
    const validStatus = ["pending", "processing", "approved", "rejected"].includes(status) ? status : "";
    const filter = validStatus ? { status: validStatus } : {};
    const rows = await models.WalletTransaction.find(filter).sort({ id: -1 }).limit(300).lean();
    const userIds = [...new Set(rows.map(row => row.userId))];
    const [users, bankAccounts] = await Promise.all([
        models.User.find({ id: { $in: userIds } }).select("id name phone").lean(),
        models.BankAccount.find({ userId: { $in: userIds } })
            .select("userId holderName bankName accountLast4 ifsc").lean()
    ]);
    const userMap = new Map(users.map(user => [user.id, user]));
    const bankMap = new Map(bankAccounts.map(account => [account.userId, account]));
    rows.sort((a, b) => {
        const order = { pending: 0, processing: 1 };
        return (order[a.status] ?? 2) - (order[b.status] ?? 2) || b.id - a.id;
    });
    res.json({
        success: true,
        transactions: rows.map(transaction => {
            const user = userMap.get(transaction.userId) || {};
            const bank = bankMap.get(transaction.userId) || {};
            return {
                id: transaction.id, userId: transaction.userId, userName: user.name || "",
                phone: user.phone || "", type: transaction.type, amountPaise: transaction.amountPaise,
                status: transaction.status, reference: transaction.reference, note: transaction.note,
                createdAt: transaction.createdAt, reviewedAt: transaction.reviewedAt,
                bankHolderName: bank.holderName || null, bankName: bank.bankName || null,
                bankAccountLast4: bank.accountLast4 || null, bankIfsc: bank.ifsc || null
            };
        })
    });
}));

app.post("/api/admin/transactions/:id/payout-details", asyncRoute(async (req, res) => {
    const transactionId = /^\d+$/.test(req.params.id) ? Number(req.params.id) : NaN;
    if (!Number.isSafeInteger(transactionId) || transactionId < 1) {
        return res.status(400).json({ success: false, message: "Invalid transaction ID." });
    }
    const transaction = await models.WalletTransaction.findOne({ id: transactionId })
        .select("userId type status").lean();
    if (!transaction || transaction.type !== "withdrawal"
        || !["pending", "processing"].includes(transaction.status)) {
        return res.status(409).json({
            success: false,
            message: "Only active withdrawal requests can reveal payout details."
        });
    }
    const account = await models.BankAccount.findOne({ userId: transaction.userId }).lean();
    if (!account) {
        return res.status(404).json({
            success: false, message: "The customer has not configured a bank account."
        });
    }
    let accountNumber;
    try {
        accountNumber = decryptBankAccount(account);
    } catch (error) {
        console.error("Bank account decryption failed for withdrawal", transactionId, error);
        return res.status(500).json({
            success: false, message: "Could not decrypt payout details. Check the bank encryption key."
        });
    }
    await auditAdmin(req.session.admin.id, "reveal_withdrawal_bank_details", "transaction", transactionId, {
        userId: transaction.userId
    });
    res.set("Cache-Control", "no-store");
    res.json({
        success: true,
        payoutDetails: {
            holderName: account.holderName, bankName: account.bankName, accountNumber, ifsc: account.ifsc
        }
    });
}));

app.get("/api/admin/mission-claims", asyncRoute(async (req, res) => {
    const status = typeof req.query.status === "string"
        && ["pending", "approved", "rejected"].includes(req.query.status) ? req.query.status : "";
    const claims = await models.MissionClaim.find(status ? { status } : {})
        .sort({ id: -1 }).limit(300).lean();
    const userIds = [...new Set(claims.map(item => item.userId))];
    const missionIds = [...new Set(claims.map(item => item.missionId))];
    const [users, missions] = await Promise.all([
        models.User.find({ id: { $in: userIds } }).select("id name phone").lean(),
        models.Mission.find({ id: { $in: missionIds } })
            .select("id name targetMembers rewardPaise").lean()
    ]);
    const userMap = new Map(users.map(user => [user.id, user]));
    const missionMap = new Map(missions.map(mission => [mission.id, mission]));
    res.json({
        success: true,
        claims: claims.map(claim => {
            const user = userMap.get(claim.userId) || {};
            const mission = missionMap.get(claim.missionId) || {};
            return {
                id: claim.id, userId: claim.userId, userName: user.name || "", phone: user.phone || "",
                missionId: claim.missionId, missionName: mission.name || "",
                targetMembers: mission.targetMembers, rewardPaise: mission.rewardPaise,
                status: claim.status, note: claim.note, createdAt: claim.createdAt, reviewedAt: claim.reviewedAt
            };
        })
    });
}));

app.get("/api/admin/product-requests", asyncRoute(async (req, res) => {
    const status = typeof req.query.status === "string"
        && ["pending", "approved", "rejected"].includes(req.query.status) ? req.query.status : "";
    const requests = await models.ProductRequest.find(status ? { status } : {})
        .sort({ id: -1 }).limit(300).lean();
    const users = await models.User.find({ id: { $in: [...new Set(requests.map(item => item.userId))] } })
        .select("id name phone").lean();
    const userMap = new Map(users.map(user => [user.id, user]));
    res.json({
        success: true,
        requests: requests.map(item => {
            const user = userMap.get(item.userId) || {};
            return {
                id: item.id, userId: item.userId, userName: user.name || "", phone: user.phone || "",
                productId: item.productId, productName: item.productName, pricePaise: item.pricePaise,
                status: item.status, note: item.note, createdAt: item.createdAt, reviewedAt: item.reviewedAt
            };
        })
    });
}));

app.post("/api/admin/product-requests/:id/review", asyncRoute(async (req, res) => {
    const requestId = Number.parseInt(req.params.id, 10);
    const decision = req.body.decision;
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!Number.isSafeInteger(requestId) || !["approved", "rejected"].includes(decision) || !note) {
        return res.status(400).json({
            success: false, message: "Choose a decision and enter a review note."
        });
    }
    const result = await models.ProductRequest.updateOne(
        { id: requestId, status: "pending" },
        { $set: {
            status: decision, note, reviewedByAdminId: req.session.admin.id, reviewedAt: new Date()
        } }
    );
    if (!result.modifiedCount) {
        return res.status(409).json({ success: false, message: "Request not found or already reviewed." });
    }
    await auditAdmin(req.session.admin.id, `product_request_${decision}`, "product_request", requestId, { note });
    res.json({
        success: true,
        message: "Request reviewed. Product purchase and rewards remain inactive pending a configured fulfilment flow."
    });
}));

app.post("/api/admin/mission-claims/:id/review", asyncRoute(async (req, res) => {
    const claimId = Number.parseInt(req.params.id, 10);
    const decision = req.body.decision;
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!Number.isSafeInteger(claimId) || !["approved", "rejected"].includes(decision) || !note) {
        return res.status(400).json({
            success: false, message: "Choose a decision and enter a review note."
        });
    }
    const result = await withTransaction(async dbSession => {
        const claim = await models.MissionClaim.findOne({ id: claimId }).session(dbSession).lean();
        if (!claim) return { error: "Mission claim not found.", status: 404 };
        if (claim.status !== "pending") return { error: "This claim has already been reviewed.", status: 409 };
        const mission = await models.Mission.findOne({ id: claim.missionId }).session(dbSession).lean();
        if (decision === "approved" && (!mission || !mission.active
            || await countActiveTeamMembers(claim.userId) < mission.targetMembers)) {
            return {
                error: "The mission is inactive or the member no longer meets its team requirement.",
                status: 409
            };
        }
        if (decision === "approved" && mission.rewardPaise > 0) {
            await models.User.updateOne(
                { id: claim.userId }, { $inc: { balancePaise: mission.rewardPaise } }, { session: dbSession }
            );
            await models.WalletTransaction.create([{
                id: await nextId("wallet_transactions", dbSession),
                userId: claim.userId, type: "adjustment", amountPaise: mission.rewardPaise,
                status: "approved", note: `Mission claim #${claimId}: ${note}`,
                createdByAdminId: req.session.admin.id, reviewedByAdminId: req.session.admin.id,
                reviewedAt: new Date()
            }], { session: dbSession });
        }
        const update = await models.MissionClaim.updateOne(
            { id: claimId, status: "pending" },
            { $set: {
                status: decision, note, reviewedByAdminId: req.session.admin.id, reviewedAt: new Date()
            } },
            { session: dbSession }
        );
        if (!update.modifiedCount) return { error: "This claim has already been reviewed.", status: 409 };
        await auditAdmin(req.session.admin.id, `mission_claim_${decision}`, "mission_claim", claimId, {
            userId: claim.userId,
            missionId: claim.missionId,
            rewardPaise: decision === "approved" ? mission.rewardPaise : 0,
            note
        }, dbSession);
        return { success: true };
    });
    if (result.error) return res.status(result.status).json({ success: false, message: result.error });
    res.json({ success: true });
}));

app.post("/api/admin/transactions", asyncRoute(async (req, res) => {
    const userId = Number.parseInt(req.body.userId, 10);
    const type = req.body.type;
    const amountPaise = parseRupees(req.body.amount);
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    const reference = typeof req.body.reference === "string" ? req.body.reference.trim().slice(0, 120) : "";
    if (!Number.isSafeInteger(userId) || !["recharge", "withdrawal"].includes(type)
        || !amountPaise || amountPaise < 0 || !note) {
        return res.status(400).json({ success: false, message: "Check transaction fields and try again." });
    }
    const transactionId = await withTransaction(async dbSession => {
        const user = await models.User.findOne({ id: userId }).session(dbSession).lean();
        if (!user) return null;
        if (type === "withdrawal") {
            const reserved = await models.User.updateOne({
                id: userId,
                $expr: { $gte: ["$balancePaise", { $add: ["$reservedWithdrawalPaise", amountPaise] }] }
            }, { $inc: { reservedWithdrawalPaise: amountPaise } }, { session: dbSession });
            if (!reserved.modifiedCount) return false;
        }
        const id = await nextId("wallet_transactions", dbSession);
        await models.WalletTransaction.create([{
            id, userId, type, amountPaise, status: "pending", reference, note,
            createdByAdminId: req.session.admin.id
        }], { session: dbSession });
        await auditAdmin(req.session.admin.id, "create_transaction", "transaction", id, {
            userId, type, amountPaise
        }, dbSession);
        return id;
    });
    if (transactionId === null) return res.status(404).json({ success: false, message: "User not found." });
    if (transactionId === false) {
        return res.status(400).json({ success: false, message: "Amount exceeds the user's available balance." });
    }
    res.status(201).json({ success: true, id: transactionId });
}));

app.post("/api/admin/transactions/:id/review", asyncRoute(async (req, res) => {
    const transactionId = Number.parseInt(req.params.id, 10);
    const decision = req.body.decision;
    const note = typeof req.body.note === "string" ? req.body.note.trim().slice(0, 250) : "";
    if (!Number.isSafeInteger(transactionId) || !["processing", "approved", "rejected"].includes(decision) || !note) {
        return res.status(400).json({
            success: false, message: "Choose a valid decision and enter a review note."
        });
    }
    const result = await withTransaction(async dbSession => {
        const transaction = await models.WalletTransaction.findOne({ id: transactionId }).session(dbSession).lean();
        if (!transaction) return { error: "Transaction not found.", status: 404 };
        if (decision === "processing") {
            if (transaction.type !== "withdrawal" || transaction.status !== "pending") {
                return { error: "Only pending withdrawal requests can be moved to processing.", status: 409 };
            }
            if (!await models.BankAccount.exists({ userId: transaction.userId }).session(dbSession)) {
                return { error: "Customer has not configured a bank account.", status: 409 };
            }
        } else if (!["pending", "processing"].includes(transaction.status)
            || (transaction.type !== "withdrawal" && transaction.status !== "pending")) {
            return { error: "This transaction has already been reviewed.", status: 409 };
        }
        if (decision === "approved" && transaction.type === "withdrawal") {
            if (!await models.BankAccount.exists({ userId: transaction.userId }).session(dbSession)) {
                return { error: "Customer has not configured a bank account.", status: 409 };
            }
            const debit = await models.User.updateOne({
                id: transaction.userId,
                balancePaise: { $gte: transaction.amountPaise },
                reservedWithdrawalPaise: { $gte: transaction.amountPaise }
            }, {
                $inc: {
                    balancePaise: -transaction.amountPaise,
                    reservedWithdrawalPaise: -transaction.amountPaise
                }
            }, { session: dbSession });
            if (!debit.modifiedCount) {
                return { error: "Insufficient available balance for this withdrawal.", status: 409 };
            }
        } else if (decision === "rejected" && transaction.type === "withdrawal") {
            await models.User.updateOne(
                { id: transaction.userId },
                { $inc: { reservedWithdrawalPaise: -transaction.amountPaise } },
                { session: dbSession }
            );
        } else if (decision === "approved" && transaction.type === "recharge") {
            await models.User.updateOne(
                { id: transaction.userId },
                { $inc: { balancePaise: transaction.amountPaise } },
                { session: dbSession }
            );
        }
        const update = await models.WalletTransaction.updateOne(
            {
                id: transactionId,
                status: transaction.status
            },
            {
                $set: {
                    status: decision,
                    ...(note ? { reference: note } : {}),
                    note,
                    reviewedByAdminId: req.session.admin.id,
                    reviewedAt: new Date()
                }
            },
            { session: dbSession }
        );
        if (!update.modifiedCount) return { error: "This transaction has already been reviewed.", status: 409 };
        await auditAdmin(req.session.admin.id, `transaction_${decision}`, "transaction", transactionId, {
            userId: transaction.userId, type: transaction.type,
            amountPaise: transaction.amountPaise, note
        }, dbSession);
        return { success: true };
    });
    if (result.error) return res.status(result.status).json({ success: false, message: result.error });
    res.json({ success: true });
}));

app.get("/api/admin/settings", asyncRoute(async (req, res) => {
    const settings = await models.SiteSetting.find().sort({ key: 1 }).lean();
    res.json({
        success: true,
        settings: settings.map(item => ({ key: item.key, value: item.value, updatedAt: item.updatedAt }))
    });
}));

const welcomePopupSettingKeys = [
    "welcome_popup_title", "welcome_popup_subtitle",
    "welcome_popup_signup_reward_label", "welcome_popup_signup_reward_value",
    "welcome_popup_invite_tracking_label", "welcome_popup_invite_tracking_value",
    "welcome_popup_min_withdrawal_label", "welcome_popup_min_recharge_label",
    "welcome_popup_payout_processing_label", "welcome_popup_payout_processing_value",
    "welcome_popup_cta_text", "welcome_popup_close_label"
];

app.put("/api/admin/welcome-popup", asyncRoute(async (req, res) => {
    const values = req.body.values;
    if (!values || typeof values !== "object" || Array.isArray(values)
        || welcomePopupSettingKeys.some(key => typeof values[key] !== "string" || values[key].trim().length > 200)) {
        return res.status(400).json({
            success: false, message: "Enter valid welcome popup text (up to 200 characters per field)."
        });
    }
    const operations = welcomePopupSettingKeys.map(key => ({
        updateOne: {
            filter: { key },
            update: { $set: { key, value: values[key].trim(), updatedByAdminId: req.session.admin.id } },
            upsert: true
        }
    }));
    await models.SiteSetting.bulkWrite(operations);
    await auditAdmin(req.session.admin.id, "update_welcome_popup", "setting", "welcome_popup", {
        fields: welcomePopupSettingKeys.length
    });
    res.json({ success: true });
}));

app.put("/api/admin/settings/:key", asyncRoute(async (req, res) => {
    const key = req.params.key;
    const value = typeof req.body.value === "string" ? req.body.value.trim() : "";
    if (!/^[a-z][a-z0-9_]{1,63}$/.test(key) || value.length > 500) {
        return res.status(400).json({ success: false, message: "Invalid setting key or value." });
    }
    if (key === "minimum_withdrawal_rupees") {
        const numericValue = Number(value);
        if (!Number.isFinite(numericValue) || numericValue < 0 || numericValue > 10000000) {
            return res.status(400).json({
                success: false, message: "Setting must be a valid non-negative amount."
            });
        }
    }
    if (key === "maintenance_mode" && !["true", "false"].includes(value)) {
        return res.status(400).json({ success: false, message: "Maintenance mode must be true or false." });
    }
    if (["site_logo_url", "site_banner_url", "invite_banner_url", "site_spinner_url"].includes(key)
        && !(key === "invite_banner_url" && value === "")
        && !/^\/(?:assets\/images\/[a-zA-Z0-9_-]+\.(?:svg|png|jpe?g|webp)|uploads\/media\/[a-f0-9]{32}\.(?:png|jpg|webp))$/.test(value)) {
        return res.status(400).json({
            success: false,
            message: "Choose a valid image from the site image library or upload one."
        });
    }
    await models.SiteSetting.updateOne(
        { key },
        { $set: { key, value, updatedByAdminId: req.session.admin.id } },
        { upsert: true }
    );
    await auditAdmin(req.session.admin.id, "update_setting", "setting", key, { value });
    res.json({ success: true });
}));

app.get("/api/admin/audit", asyncRoute(async (req, res) => {
    const rows = await models.AdminAudit.find().sort({ id: -1 }).limit(200).lean();
    const admins = await models.Admin.find({ id: { $in: [...new Set(rows.map(row => row.adminId))] } })
        .select("id displayUsername").lean();
    const adminNames = new Map(admins.map(admin => [
        admin.id, admin.displayUsername || admin.username
    ]));
    res.json({
        success: true,
        events: rows.map(row => ({
            id: row.id, action: row.action, entityType: row.entityType, entityId: row.entityId,
            details: JSON.stringify(row.details || {}), createdAt: row.createdAt,
            username: adminNames.get(row.adminId) || ""
        }))
    });
}));

app.get("/assets/images/sprite-logo.png", asyncRoute(async (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(await siteImagePath("site_logo_url", "sprite-logo.png"));
}));
app.get("/assets/images/hero.svg", asyncRoute(async (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(await siteImagePath("site_banner_url", "money-hero.png"));
}));
app.get("/assets/images/money-hero.svg", (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(path.join(__dirname, "assets", "images", "money-hero.png"));
});
app.get("/assets/images/Speener.svg", asyncRoute(async (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(await siteImagePath("site_spinner_url", "Speener.png"));
}));
app.use("/uploads", express.static(path.join(__dirname, "uploads"), { dotfiles: "deny" }));
app.use("/assets", express.static(path.join(__dirname, "assets"), { dotfiles: "deny" }));

const protectedPages = new Set([
    "home.html", "mine.html", "invite.html", "account.html", "my-products.html", "bank-setup.html",
    "transactions.html", "spin.html", "recharge.html", "mission.html", "team.html", "withdrawal.html",
    "mock-checkout.html"
]);
const legacyPageAliases = new Map([
    ["/pages/home", "home.html"], ["/pages/recharge", "recharge.html"],
    ["/pages/withdrawal", "withdrawal.html"], ["/pages/mission", "mission.html"],
    ["/pages/invite", "invite.html"], ["/pages/spin", "spin.html"], ["/pages/team", "team.html"],
    ["/pages/mine", "mine.html"], ["/pages/account", "account.html"],
    ["/pages/my-products", "my-products.html"], ["/pages/transactions", "transactions.html"]
]);

async function sendPage(req, res, page) {
    const filepath = path.join(__dirname, page);
    if (!req.session.impersonation) return res.sendFile(filepath);
    let html;
    try {
        html = await fs.promises.readFile(filepath, "utf8");
    } catch (error) {
        console.error(`Could not load support-access page ${page}:`, error);
        return res.status(500).type("text").send("Could not load this page.");
    }
    const target = await models.User.findOne({ id: req.session.impersonation.userId })
        .select("name").lean();
    if (!target) return res.status(401).redirect("/admin/");
    const safeName = target.name.replace(/[&<>"']/g, character => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
    })[character]);
    const csrfToken = req.session.csrfToken;
    const bar = `<aside id="supportAccessBar" style="position:sticky;top:0;z-index:99999;background:#261b0d;color:#fff;padding:11px 16px;text-align:center;font:14px system-ui,sans-serif">Admin support access for <strong>${safeName}</strong> — user actions are visible. <button id="returnToAdmin" type="button" style="margin-left:12px;border:0;border-radius:6px;padding:8px 12px;background:#f2c14e;color:#261b0d;font-weight:700;cursor:pointer">Return to admin</button><span id="supportAccessError" role="status" style="margin-left:8px"></span></aside><script>(function(){const button=document.getElementById("returnToAdmin");button.addEventListener("click",async function(){button.disabled=true;try{const response=await fetch("/api/admin/impersonation/stop",{method:"POST",headers:{"X-CSRF-Token":"${csrfToken}"}});const result=await response.json();if(!response.ok)throw new Error(result.message||"Could not return to admin.");window.location.replace("/admin/");}catch(error){document.getElementById("supportAccessError").textContent=error.message;button.disabled=false;}});})();</script>`;
    const bodyTag = /<body\b[^>]*>/i;
    if (!bodyTag.test(html)) {
        return res.status(500).type("text").send("Support access page is missing a body element.");
    }
    res.set("Cache-Control", "no-store");
    res.type("html").send(html.replace(bodyTag, match => `${match}${bar}`));
}

function sendLoginPage(req, res) {
    if (req.session.impersonation || req.session.user) return res.redirect(302, "/home.html");
    return sendPage(req, res, "index.html");
}
app.get("/", asyncRoute(async (req, res) => sendLoginPage(req, res)));
app.get("/index.html", asyncRoute(async (req, res) => sendLoginPage(req, res)));
app.get("/about.html", asyncRoute(async (req, res) => sendPage(req, res, "about.html")));

const serveProtectedPage = page => asyncRoute(async (req, res) => {
    if (req.session.impersonation && !req.session.user) return res.redirect(302, "/admin/");
    if (!req.session.user) return res.redirect(302, "/index.html");
    const user = await models.User.findOne({ id: req.session.user.id })
        .select("status credentialVersion").lean();
    if (!user || user.status !== "active" || !credentialVersionMatches(req.session.user, user)) {
        if (req.session.impersonation && req.session.admin) {
            if (await restoreAdminSession(req)) return res.redirect(302, "/admin/");
        }
        await destroySession(req, res);
        return res.redirect(302, "/index.html");
    }
    await sendPage(req, res, page);
});
for (const page of protectedPages) app.get(`/${page}`, serveProtectedPage(page));
for (const [alias, page] of legacyPageAliases) app.get(alias, serveProtectedPage(page));
app.get(["/admin", "/admin.html"], asyncRoute(async (req, res) => {
    res.set("Cache-Control", "no-store");
    if (req.session.impersonation) return res.redirect(302, "/home.html");
    await sendPage(req, res, "admin.html");
}));

app.use((req, res) => {
    res.status(404).json({ success: false, message: "Not found." });
});
app.use((error, req, res, next) => {
    console.error("Request failed:", error);
    if (res.headersSent) return next(error);
    if (error.type === "entity.too.large") {
        return res.status(413).json({ success: false, message: "Image uploads must be 3 MB or smaller." });
    }
    if (error.type === "entity.parse.failed") {
        return res.status(400).json({ success: false, message: "Request body is invalid." });
    }
    res.status(500).json({ success: false, message: "Server error. Please try again." });
});

module.exports = app;
