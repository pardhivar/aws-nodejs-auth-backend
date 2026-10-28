require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const mongoose = require("mongoose");
const { rateLimit } = require("express-rate-limit");
const authRoutes = require("./routes/auth");

const app = express();
const port = Number(process.env.PORT || 3000);

app.disable("x-powered-by");

// Trust only the local Nginx reverse proxy on this same server.
app.set("trust proxy", "loopback");

app.use(helmet());
app.use(express.json({ limit: "1mb" }));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests. Try again later." },
});

app.get("/", (_req, res) => {
    res.send("Welcome to my home page");
});

app.get("/health", (_req, res) => {
    const connected = mongoose.connection.readyState === 1;

    res.status(connected ? 200 : 503).json({
        status: connected ? "ok" : "unavailable",
        database: connected ? "connected" : "disconnected",
    });
});

app.use("/api/auth", authLimiter, authRoutes);

async function startServer() {
    const mongoUri = process.env.MONGODB_URI;
    const jwtSecret = process.env.JWT_SECRET;

    if (!mongoUri) {
        throw new Error("MONGODB_URI is not configured.");
    }

    if (!jwtSecret || jwtSecret.length < 32) {
        throw new Error(
            "JWT_SECRET must be set to a random secret of at least 32 characters."
        );
    }

    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error("PORT must be an integer between 1 and 65535.");
    }

    await mongoose.connect(mongoUri);
    console.log("Database connected");

    // Bind to loopback: Nginx will proxy public requests to this port.
    const server = app.listen(port, "0.0.0.0", () => {
    console.log(`Server listening on port ${port}`);
});

    let shuttingDown = false;

    const shutdown = (signal) => {
        if (shuttingDown) return;

        shuttingDown = true;
        console.log(`Received ${signal}; shutting down`);

        const forceTimer = setTimeout(() => {
            console.error("Graceful shutdown timed out; exiting");
            process.exit(1);
        }, 10000);

        forceTimer.unref();

        server.close(async () => {
            try {
                await mongoose.disconnect();
                console.log("Database disconnected");
            } catch (error) {
                console.error(
                    "MongoDB disconnect failed:",
                    error.name || "Error"
                );
                process.exitCode = 1;
            }
        });
    };

    process.once("SIGINT", () => shutdown("SIGINT"));
    process.once("SIGTERM", () => shutdown("SIGTERM"));
}

startServer().catch((error) => {
    console.error("Server startup failed:", error.message);
    process.exitCode = 1;
});
