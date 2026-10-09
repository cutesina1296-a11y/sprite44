"use strict";

const mongoose = require("mongoose");

const { Schema } = mongoose;

const counterSchema = new Schema({
    _id: { type: String },
    sequence: { type: Number, required: true, default: 0 }
}, { versionKey: false });

const userSchema = new Schema({
    id: { type: Number, required: true, unique: true },
    name: { type: String, required: true },
    phone: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    balancePaise: { type: Number, required: true, default: 0 },
    reservedWithdrawalPaise: { type: Number, required: true, default: 0 },
    status: { type: String, required: true, default: "active", enum: ["active", "suspended"] },
    referralCode: { type: String, required: true, unique: true },
    referredByUserId: { type: Number, default: null }
}, { timestamps: true, versionKey: false });
userSchema.index({ referredByUserId: 1 });

const adminSchema = new Schema({
    id: { type: Number, required: true, unique: true },
    username: { type: String, required: true, lowercase: true },
    displayUsername: { type: String, required: true },
    passwordHash: { type: String, required: true },
    passwordChangeRequired: { type: Boolean, required: true, default: true },
    lastLoginAt: { type: Date, default: null }
}, { timestamps: true, versionKey: false });
adminSchema.index({ username: 1 }, {
    unique: true,
    collation: { locale: "en", strength: 2 }
});

const productSchema = new Schema({
    id: { type: Number, required: true, unique: true },
    name: { type: String, required: true },
    category: { type: String, required: true, enum: ["daily", "vip"] },
    pricePaise: { type: Number, required: true, min: 0 },
    durationDays: { type: Number, required: true, min: 1 },
    dailyRewardPaise: { type: Number, required: true, default: 0, min: 0 },
    totalRewardPaise: { type: Number, required: true, default: 0, min: 0 },
    purchaseLimit: { type: Number, required: true, default: 1, min: 1 },
    active: { type: Boolean, required: true, default: true },
    imageUrl: { type: String, default: "" }
}, { timestamps: true, versionKey: false });

const missionSchema = new Schema({
    id: { type: Number, required: true, unique: true },
    name: { type: String, required: true },
    description: { type: String, default: "" },
    targetMembers: { type: Number, required: true, min: 0 },
    rewardPaise: { type: Number, required: true, min: 0 },
    active: { type: Boolean, required: true, default: true }
}, { timestamps: true, versionKey: false });

const walletTransactionSchema = new Schema({
    id: { type: Number, required: true, unique: true },
    userId: { type: Number, required: true, index: true },
    type: { type: String, required: true, enum: ["recharge", "withdrawal", "adjustment"] },
    amountPaise: { type: Number, required: true, validate: value => value !== 0 },
    status: { type: String, required: true, enum: ["pending", "processing", "approved", "rejected"] },
    reference: { type: String, default: "" },
    note: { type: String, default: "" },
    createdByAdminId: { type: Number, default: null },
    reviewedByAdminId: { type: Number, default: null },
    reviewedAt: { type: Date, default: null }
}, { timestamps: { createdAt: true, updatedAt: false }, versionKey: false });
walletTransactionSchema.index({ status: 1, createdAt: -1 });
walletTransactionSchema.index({ userId: 1, type: 1, status: 1, id: -1 });

const siteSettingSchema = new Schema({
    key: { type: String, required: true, unique: true },
    value: { type: String, required: true },
    updatedByAdminId: { type: Number, default: null }
}, { timestamps: { createdAt: false, updatedAt: true }, versionKey: false });

const adminAuditSchema = new Schema({
    id: { type: Number, required: true, unique: true },
    adminId: { type: Number, required: true },
    action: { type: String, required: true },
    entityType: { type: String, required: true },
    entityId: { type: String, default: "" },
    details: { type: Schema.Types.Mixed, default: {} }
}, { timestamps: { createdAt: true, updatedAt: false }, versionKey: false });

const missionClaimSchema = new Schema({
    id: { type: Number, required: true, unique: true },
    userId: { type: Number, required: true },
    missionId: { type: Number, required: true },
    status: { type: String, required: true, enum: ["pending", "approved", "rejected"] },
    note: { type: String, default: "" },
    reviewedByAdminId: { type: Number, default: null },
    reviewedAt: { type: Date, default: null }
}, { timestamps: true, versionKey: false });
missionClaimSchema.index({ userId: 1, missionId: 1 }, { unique: true });
missionClaimSchema.index({ status: 1, createdAt: -1 });

const productRequestSchema = new Schema({
    id: { type: Number, required: true, unique: true },
    userId: { type: Number, required: true },
    productId: { type: Number, required: true },
    productName: { type: String, required: true },
    pricePaise: { type: Number, required: true, min: 0 },
    status: { type: String, required: true, enum: ["pending", "approved", "rejected"] },
    note: { type: String, default: "" },
    reviewedByAdminId: { type: Number, default: null },
    reviewedAt: { type: Date, default: null }
}, { timestamps: true, versionKey: false });
productRequestSchema.index({ status: 1, createdAt: -1 });

const demoAccountSchema = new Schema({
    id: { type: Number, required: true, unique: true },
    demoCode: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    balancePaise: { type: Number, required: true, default: 0 },
    createdByAdminId: { type: Number, required: true }
}, { timestamps: true, versionKey: false });

const demoWalletTransactionSchema = new Schema({
    id: { type: Number, required: true, unique: true },
    demoAccountId: { type: Number, required: true },
    type: { type: String, required: true, enum: ["demo_deposit", "demo_withdrawal"] },
    amountPaise: { type: Number, required: true, min: 1 },
    note: { type: String, required: true },
    createdByAdminId: { type: Number, required: true }
}, { timestamps: { createdAt: true, updatedAt: false }, versionKey: false });
demoWalletTransactionSchema.index({ demoAccountId: 1, id: -1 });

const bankAccountSchema = new Schema({
    userId: { type: Number, required: true, unique: true },
    holderName: { type: String, required: true },
    bankName: { type: String, required: true },
    accountCiphertext: { type: String, required: true },
    accountIv: { type: String, required: true },
    accountTag: { type: String, required: true },
    accountLast4: { type: String, required: true },
    ifsc: { type: String, required: true }
}, { timestamps: true, versionKey: false });

const userProductSchema = new Schema({
    id: { type: Number, required: true, unique: true },
    userId: { type: Number, required: true },
    productId: { type: Number, required: true },
    productName: { type: String, required: true },
    pricePaise: { type: Number, required: true, min: 0 },
    durationDays: { type: Number, required: true, min: 1 },
    purchasedAt: { type: Date, required: true, default: Date.now },
    expiresAt: { type: Date, required: true },
    status: { type: String, required: true, enum: ["active", "expired"], default: "active" }
}, { versionKey: false });
userProductSchema.index({ userId: 1, status: 1, expiresAt: 1 });

const sessionSchema = new Schema({
    sid: { type: String, required: true, unique: true },
    data: { type: Schema.Types.Mixed, required: true },
    expiresAt: { type: Date, required: true }
}, { versionKey: false });
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

function model(name, schema, collection) {
    return mongoose.models[name] || mongoose.model(name, schema, collection);
}

module.exports = {
    Counter: model("Counter", counterSchema, "counters"),
    User: model("User", userSchema, "users"),
    Admin: model("Admin", adminSchema, "admins"),
    Product: model("Product", productSchema, "products"),
    Mission: model("Mission", missionSchema, "missions"),
    WalletTransaction: model("WalletTransaction", walletTransactionSchema, "wallet_transactions"),
    SiteSetting: model("SiteSetting", siteSettingSchema, "site_settings"),
    AdminAudit: model("AdminAudit", adminAuditSchema, "admin_audit"),
    MissionClaim: model("MissionClaim", missionClaimSchema, "mission_claims"),
    ProductRequest: model("ProductRequest", productRequestSchema, "product_requests"),
    DemoAccount: model("DemoAccount", demoAccountSchema, "demo_accounts"),
    DemoWalletTransaction: model("DemoWalletTransaction", demoWalletTransactionSchema, "demo_wallet_transactions"),
    BankAccount: model("BankAccount", bankAccountSchema, "bank_accounts"),
    UserProduct: model("UserProduct", userProductSchema, "user_products"),
    Session: model("Session", sessionSchema, "sessions")
};
