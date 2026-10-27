const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();

function isValidEmail(email) {
    return (
        typeof email === "string" &&
        email.length <= 254 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    );
}

function issueToken(user) {
    return jwt.sign({ sub: user.id }, process.env.JWT_SECRET, {
        expiresIn: "1h",
    });
}

router.post("/register", async (req, res, next) => {
    const { email, password } = req.body || {};
    const passwordBytes =
        typeof password === "string" ? Buffer.byteLength(password, "utf8") : 0;

    if (
        !isValidEmail(email) ||
        typeof password !== "string" ||
        passwordBytes < 8 ||
        passwordBytes > 72
    ) {
        return res.status(400).json({
            error: "Provide a valid email and a password of 8 to 72 bytes.",
        });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 12);
        const user = await User.create({
            email: email.trim().toLowerCase(),
            passwordHash,
        });

        return res.status(201).json({
            token: issueToken(user),
            user: { id: user.id, email: user.email },
        });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({ error: "Email is already registered." });
        }

        return next(error);
    }
});

router.post("/login", async (req, res, next) => {
    const { email, password } = req.body || {};

    if (typeof email !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "Email and password are required." });
    }

    try {
        const user = await User.findOne({
            email: email.trim().toLowerCase(),
        }).select("+passwordHash");

        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).json({ error: "Invalid email or password." });
        }

        return res.json({
            token: issueToken(user),
            user: { id: user.id, email: user.email },
        });
    } catch (error) {
        return next(error);
    }
});

module.exports = router;
