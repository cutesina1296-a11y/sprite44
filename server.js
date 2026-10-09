"use strict";

require("dotenv").config();

const { connectMongoDB, initializeMongoDB } = require("./database");

connectMongoDB()
    .then(() => {
        return initializeMongoDB();
    })
    .then(() => {
        const app = require("./app");
        const port = Number(process.env.PORT || 3000);
        app.listen(port, () => {
            console.log(`Finora server listening on port ${port}`);
        });
    })
    .catch(async error => {
        if (error.message === "MONGODB_URI must be configured before server startup.") {
            console.error(error.message);
        } else {
            const safeMessage = String(error.message || "Unknown startup error")
                .replace(/mongodb(?:\+srv)?:\/\/[^\s"'`]+/gi, "[redacted MongoDB URI]");
            console.error("Application startup failed; server was not started.", error.name, safeMessage);
        }
        await require("mongoose").disconnect().catch(disconnectError => {
            console.error("Could not close MongoDB after startup failure:", disconnectError.name);
        });
        process.exitCode = 1;
    });
