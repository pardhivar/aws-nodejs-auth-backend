require("dotenv").config();

const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const helmet = require("helmet");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { rateLimit } = require("express-rate-limit");
const authRoutes = require("./routes/auth");
const User = require("./models/User");

const app = express();
const port = Number(process.env.PORT || 3000);
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024,
    },
});

const s3Client = new S3Client({
    region: process.env.AWS_REGION,
    credentials:
        process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY
            ? {
                  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
                  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
              }
            : undefined,
});

app.disable("x-powered-by");
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Trust only the local Nginx reverse proxy on this same server.
app.set("trust proxy", "loopback");

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                baseUri: ["'self'"],
                formAction: ["'self'"],
                frameAncestors: ["'self'"],
                objectSrc: ["'none'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                fontSrc: ["'self'", "https:", "data:"],
                imgSrc: ["'self'", "data:", "https://*.amazonaws.com"],
            },
        },
    })
);
app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many requests. Try again later." },
});

function issueToken(user) {
    return jwt.sign({ sub: user.id }, process.env.JWT_SECRET, {
        expiresIn: "1h",
    });
}

function requireAuth(req, res, next) {
    const token = req.cookies?.token;

    if (!token) {
        return res.redirect("/login");
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);
        req.user = { id: payload.sub };
        return next();
    } catch (error) {
        res.clearCookie("token");
        return res.redirect("/login");
    }
}

app.get("/", (req, res) => {
    if (req.cookies?.token) {
        try {
            jwt.verify(req.cookies.token, process.env.JWT_SECRET);
            return res.redirect("/dashboard");
        } catch (error) {
            res.clearCookie("token");
        }
    }

    res.render("landing", {
        title: "S3 Image Dashboard",
    });
});

app.get("/register", (req, res) => {
    if (req.cookies?.token) {
        try {
            jwt.verify(req.cookies.token, process.env.JWT_SECRET);
            return res.redirect("/dashboard");
        } catch (error) {
            res.clearCookie("token");
        }
    }

    res.render("register", {
        error: "",
        title: "Create account",
    });
});

app.post("/register", async (req, res, next) => {
    const { email, password } = req.body || {};
    const normalizedEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
    const passwordBytes =
        typeof password === "string" ? Buffer.byteLength(password, "utf8") : 0;

    if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail) ||
        typeof password !== "string" ||
        passwordBytes < 8 ||
        passwordBytes > 72
    ) {
        return res.status(400).render("register", {
            error: "Provide a valid email and a password of 8 to 72 bytes.",
            title: "Create account",
        });
    }

    try {
        const existingUser = await User.findOne({ email: normalizedEmail });

        if (existingUser) {
            return res.status(409).render("register", {
                error: "An account with this email already exists.",
                title: "Create account",
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const user = await User.create({
            email: normalizedEmail,
            passwordHash,
        });

        const token = issueToken(user);
        res.cookie("token", token, {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: 60 * 60 * 1000,
        });

        return res.redirect("/dashboard");
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).render("register", {
                error: "An account with this email already exists.",
                title: "Create account",
            });
        }

        return next(error);
    }
});

app.get("/login", (req, res) => {
    if (req.cookies?.token) {
        try {
            jwt.verify(req.cookies.token, process.env.JWT_SECRET);
            return res.redirect("/dashboard");
        } catch (error) {
            res.clearCookie("token");
        }
    }

    res.render("login", {
        error: "",
        title: "Login",
    });
});

app.post("/login", async (req, res, next) => {
    const { email, password } = req.body || {};

    if (typeof email !== "string" || typeof password !== "string") {
        return res.status(400).render("login", {
            error: "Email and password are required.",
            title: "Login",
        });
    }

    try {
        const user = await User.findOne({
            email: email.trim().toLowerCase(),
        }).select("+passwordHash");

        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).render("login", {
                error: "Invalid email or password.",
                title: "Login",
            });
        }

        const token = issueToken(user);
        res.cookie("token", token, {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: 60 * 60 * 1000,
        });

        return res.redirect("/dashboard");
    } catch (error) {
        return next(error);
    }
});

app.get("/logout", (_req, res) => {
    res.clearCookie("token");
    res.redirect("/login");
});

app.get("/dashboard", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).lean();

        res.render("dashboard", {
            user: user ? { id: user._id.toString(), email: user.email } : null,
            uploadedImageUrl: "",
            uploadError: "",
            uploadedFileName: "",
            title: "Dashboard",
        });
    } catch (error) {
        console.error("Dashboard load failed:", error);
        res.status(500).send("Unable to load the dashboard.");
    }
});

app.post("/dashboard/upload", requireAuth, upload.single("image"), async (req, res) => {
    const user = await User.findById(req.user.id).lean();
    const file = req.file;

    if (!file) {
        return res.status(400).render("dashboard", {
            user: user ? { id: user._id.toString(), email: user.email } : null,
            uploadedImageUrl: "",
            uploadError: "Please select an image to upload.",
            uploadedFileName: "",
            title: "Dashboard",
        });
    }

    if (!file.mimetype.startsWith("image/")) {
        return res.status(400).render("dashboard", {
            user: user ? { id: user._id.toString(), email: user.email } : null,
            uploadedImageUrl: "",
            uploadError: "Only image files are allowed.",
            uploadedFileName: "",
            title: "Dashboard",
        });
    }

    if (!process.env.AWS_S3_BUCKET || !process.env.AWS_REGION) {
        return res.status(500).render("dashboard", {
            user: user ? { id: user._id.toString(), email: user.email } : null,
            uploadedImageUrl: "",
            uploadError: "Set AWS_S3_BUCKET and AWS_REGION in your environment before uploading.",
            uploadedFileName: "",
            title: "Dashboard",
        });
    }

    try {
        const safeFileName = file.originalname.replace(/\s+/g, "-");
        const key = `uploads/${req.user.id}/${Date.now()}-${safeFileName}`;

        await s3Client.send(
            new PutObjectCommand({
                Bucket: process.env.AWS_S3_BUCKET,
                Key: key,
                Body: file.buffer,
                ContentType: file.mimetype,
            })
        );

        const imageUrl = `https://${process.env.AWS_S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;

        return res.render("dashboard", {
            user: user ? { id: user._id.toString(), email: user.email } : null,
            uploadedImageUrl: imageUrl,
            uploadError: "",
            uploadedFileName: safeFileName,
            title: "Dashboard",
        });
    } catch (error) {
        console.error("S3 upload failed:", error);
        return res.status(500).render("dashboard", {
            user: user ? { id: user._id.toString(), email: user.email } : null,
            uploadedImageUrl: "",
            uploadError: "Image upload to S3 failed. Check your AWS configuration and bucket permissions.",
            uploadedFileName: "",
            title: "Dashboard",
        });
    }
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
