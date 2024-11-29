import { ApiError } from "../utils/aperror.js";
import { asyncHandler } from "../utils/assynchandler.js";
import jwt from "jsonwebtoken";
import { User } from "../model/user.model.js"; 

// JWT verification middleware
export const verifyJWT = asyncHandler(async (req, res, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");

        if (!token) {
            throw new ApiError(401, "Unauthorized: Missing token");
        }

        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken");

        if (!user) {
            throw new ApiError(401, "Unauthorized: Invalid access token");
        }
        req.user = user;
        next();
    } catch (error) {
        throw new ApiError(401, error?.message || "Unauthorized: Invalid or expired token");
    }
});

const ROLES = {
    ADMIN: "admin",
    MODERATOR: "moderator",
};

// Authentication middleware
export const verifyAuthentication = asyncHandler(async (req, res, next) => {
    try {
        const token =
            req.cookies?.accessToken ||
            req.header("Authorization")?.replace("Bearer ", "").trim();

        if (!token) {
            throw new ApiError(401, "Unauthorized: Missing access token");
        }

        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken");

        if (!user) {
            throw new ApiError(401, "Unauthorized: Invalid access token");
        }

        req.user = user;
        next();  // Ensure next() is called after assignment to req.user
    } catch (error) {
        throw new ApiError(401, "Unauthorized: Invalid or expired token");
    }
});

// Ensure only one admin is registered
export const ensureSingleAdmin = asyncHandler(async (req, res, next) => {
    const { role } = req.body;

    if (role?.toLowerCase() === "admin") {
        const existingAdmin = await User.findOne({ role: "admin" });

        if (existingAdmin) {
            throw new ApiError(403, "An admin already exists. Only one admin is allowed during registration.");
        }
    }
    next();
});
