"use strict";

const mongoose = require("mongoose");
const models = require("./models");

class TransactionOperationRejected extends Error {
    constructor(outcome) {
        super(outcome.error);
        this.outcome = outcome;
    }
}

async function connectMongoDB() {
    const uri = process.env.MONGODB_URI;
    if (typeof uri !== "string" || !uri.trim()) {
        throw new Error("MONGODB_URI must be configured before server startup.");
    }

    mongoose.connection.on("error", error => {
        console.error("MongoDB connection error:", error.name);
    });
    await mongoose.connect(uri);
    console.log("MongoDB connected.");
}

async function nextId(collection, session) {
    const counter = await models.Counter.findOneAndUpdate(
        { _id: collection },
        { $inc: { sequence: 1 } },
        { upsert: true, new: true, session }
    ).lean();
    return counter.sequence;
}

async function withTransaction(operation) {
    const session = await mongoose.startSession();
    try {
        let result;
        try {
            await session.withTransaction(async () => {
                const outcome = await operation(session);
                if (outcome && typeof outcome.error === "string") {
                    throw new TransactionOperationRejected(outcome);
                }
                result = outcome;
            });
        } catch (error) {
            if (error instanceof TransactionOperationRejected) return error.outcome;
            throw error;
        }
        return result;
    } finally {
        await session.endSession();
    }
}

async function initializeMongoDB() {
    await Promise.all(Object.values(models).map(model => model.init()));

    const collectionsWithNumericIds = {
        users: models.User,
        admins: models.Admin,
        products: models.Product,
        missions: models.Mission,
        wallet_transactions: models.WalletTransaction,
        admin_audit: models.AdminAudit,
        mission_claims: models.MissionClaim,
        product_requests: models.ProductRequest,
        demo_accounts: models.DemoAccount,
        demo_wallet_transactions: models.DemoWalletTransaction,
        user_products: models.UserProduct
    };
    await Promise.all(Object.entries(collectionsWithNumericIds).map(async ([name, collection]) => {
        const highest = await collection.findOne().sort({ id: -1 }).select("id").lean();
        if (highest && Number.isSafeInteger(highest.id)) {
            await models.Counter.updateOne(
                { _id: name },
                { $max: { sequence: highest.id } },
                { upsert: true }
            );
        }
    }));

    const initialProducts = [
        [372, "Product A", "daily", 900, 2, 4000, 8000, 5],
        [374, "Product B", "daily", 295, 45, 240, 10800, 10],
        [376, "Product C", "daily", 550, 10, 1400, 14000, 10],
        [377, "Product D", "daily", 1100, 7, 4000, 28000, 10],
        [379, "Product F", "daily", 2500, 5, 7450, 37250, 5],
        [380, "Product G", "daily", 4999, 2, 29999, 59998, 1],
        [387, "VIP 1", "vip", 999, 3, 2500, 7500, 10],
        [386, "VIP 2", "vip", 1500, 2, 6000, 12000, 10],
        [378, "VIP 3", "vip", 3000, 2, 12000, 24000, 10],
        [388, "VIP 4", "vip", 6000, 1, 50000, 50000, 1]
    ];
    if (await models.Product.countDocuments() === 0) {
        await models.Product.insertMany(initialProducts.map(
            ([id, name, category, price, duration, daily, total, limit]) => ({
                id,
                name,
                category,
                pricePaise: price * 100,
                durationDays: duration,
                dailyRewardPaise: daily * 100,
                totalRewardPaise: total * 100,
                purchaseLimit: limit
            })
        ));
    }
    const highestProductId = await models.Product.findOne().sort({ id: -1 }).select("id").lean();
    if (highestProductId) {
        await models.Counter.updateOne(
            { _id: "products" },
            { $max: { sequence: highestProductId.id } },
            { upsert: true }
        );
    }

    const initialMissions = [
        ["3 team members", "Reach 3 team members", 3, 4000],
        ["5 team members", "Reach 5 team members", 5, 120],
        ["10 team members", "Reach 10 team members", 10, 300],
        ["20 team members", "Reach 20 team members", 20, 700],
        ["35 team members", "Reach 35 team members", 35, 1500],
        ["50 team members", "Reach 50 team members", 50, 3000],
        ["100 team members", "Reach 100 team members", 100, 7000]
    ];
    if (await models.Mission.countDocuments() === 0) {
        for (const [name, description, targetMembers, reward] of initialMissions) {
            await models.Mission.create({
                id: await nextId("missions"),
                name,
                description,
                targetMembers,
                rewardPaise: reward * 100
            });
        }
    }
    await models.Mission.updateOne(
        { name: "3 team members", targetMembers: 3, rewardPaise: 5000 },
        { $set: { rewardPaise: 400000 } }
    );

    const initialSettings = [
        ["site_name", "Finora"],
        ["site_logo_url", "/assets/images/sprite-logo.png"],
        ["site_banner_url", "/assets/images/money-hero.png"],
        ["invite_banner_url", ""],
        ["site_spinner_url", "/assets/images/Speener.png"],
        ["support_url", "https://t.me/spritesupport65"],
        ["minimum_recharge_rupees", "295"],
        ["minimum_withdrawal_rupees", "170"],
        ["welcome_popup_title", "Finora"],
        ["welcome_popup_subtitle", "New app launched"],
        ["welcome_popup_signup_reward_label", "Sign up"],
        ["welcome_popup_signup_reward_value", "₹40"],
        ["welcome_popup_invite_tracking_label", "3 active members"],
        ["welcome_popup_invite_tracking_value", "₹4,000"],
        ["welcome_popup_min_withdrawal_label", "Min withdrawal"],
        ["welcome_popup_min_recharge_label", "Min Recharge"],
        ["welcome_popup_payout_processing_label", "Withdrawal time"],
        ["welcome_popup_payout_processing_value", "06:00 - 23:30"],
        ["welcome_popup_cta_text", "Join Telegram"],
        ["welcome_popup_close_label", "Close"],
        ["maintenance_mode", "false"]
    ];
    await models.SiteSetting.bulkWrite(initialSettings.map(([key, value]) => ({
        updateOne: {
            filter: { key },
            update: { $setOnInsert: { key, value } },
            upsert: true
        }
    })));
    await models.SiteSetting.updateOne(
        { key: "welcome_popup_payout_processing_label", value: "Payout processing" },
        { $set: { value: "Withdrawal time" } }
    );
    await models.SiteSetting.updateOne(
        { key: "welcome_popup_payout_processing_value", value: "Manual review only" },
        { $set: { value: "06:00 - 23:30" } }
    );
    await models.SiteSetting.updateOne(
        { key: "welcome_popup_signup_reward_value", value: "₹40 added on signup" },
        { $set: { value: "₹40" } }
    );
    await models.SiteSetting.updateOne(
        { key: "welcome_popup_signup_reward_label", value: "refer 3 active member" },
        { $set: { value: "Sign up" } }
    );
    await models.SiteSetting.updateOne(
        { key: "welcome_popup_invite_tracking_label", value: "Invite tracking" },
        { $set: { value: "3 active members" } }
    );
    await models.SiteSetting.updateOne(
        {
            key: "welcome_popup_invite_tracking_value",
            value: { $in: ["Active", "Mission reward after review", "₹50 after review"] }
        },
        { $set: { value: "₹4,000" } }
    );
    await models.SiteSetting.updateOne(
        { key: "support_url", value: "https://t.me/Kingfisher_supportbot" },
        { $set: { value: "https://t.me/spritesupport65" } }
    );
    await models.SiteSetting.updateOne(
        { key: "site_banner_url", value: "/assets/images/hero.svg" },
        { $set: { value: "/assets/images/money-hero.png" } }
    );
    await models.SiteSetting.updateOne(
        { key: "site_banner_url", value: "/assets/images/money-hero.svg" },
        { $set: { value: "/assets/images/money-hero.png" } }
    );
    await models.SiteSetting.updateOne(
        { key: "site_spinner_url", value: "/assets/images/Speener.svg" },
        { $set: { value: "/assets/images/Speener.png" } }
    );

    const adminUsername = (process.env.ADMIN_USERNAME || "").trim();
    const adminPassword = process.env.ADMIN_PASSWORD || "";
    if (Boolean(adminUsername) !== Boolean(adminPassword)) {
        throw new Error("Set both ADMIN_USERNAME and ADMIN_PASSWORD to bootstrap the first admin.");
    }
    if (adminUsername && (adminUsername.length < 3 || adminUsername.length > 64)) {
        throw new Error("ADMIN_USERNAME must be 3 to 64 characters.");
    }
    if (adminPassword && adminPassword.length < 12) {
        throw new Error("ADMIN_PASSWORD must be at least 12 characters.");
    }
    const existingAdmin = adminUsername
        ? await models.Admin.findOne({ username: adminUsername.toLowerCase() })
            .collation({ locale: "en", strength: 2 }).select("id").lean()
        : null;
    if (adminUsername && !existingAdmin) {
        const bcrypt = require("bcryptjs");
        await models.Admin.create({
            id: await nextId("admins"),
            username: adminUsername.toLowerCase(),
            displayUsername: adminUsername,
            passwordHash: await bcrypt.hash(adminPassword, 12),
            passwordChangeRequired: true
        });
        console.log("Initial admin account created; it must change its password after signing in.");
    }
}

module.exports = {
    connectMongoDB,
    initializeMongoDB,
    nextId,
    withTransaction,
    models
};
