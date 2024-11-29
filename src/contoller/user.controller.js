import { asyncHandler } from '../utils/assynchandler.js';
import { ApiResponse } from '../utils/apiresponse.js';
import { User } from '../model/user.model.js';
import { ApiError } from '../utils/aperror.js';
import mongoose from 'mongoose'; // Ensure mongoose is imported

const registerUser = asyncHandler(async (req, res) => {
    const { username, email, password, role, isActive } = req.body;

    if ([username, email, password].some((field) => !field || !field.trim())) {
        throw new ApiError(400, "All fields are compulsory");
    }

    // Check for existing user for same credentials
    const existedUser = await User.findOne({
        $or: [{ username: username.trim() }, { email: email.trim() }],
    });
    if (existedUser) {
        throw new ApiError(409, "User already exists");
    }

    // Restrict registration roles to "user" and "admin"
    const allowedRoles = ["user", "admin"];
    const finalRole = role && allowedRoles.includes(role.toLowerCase()) ? role.toLowerCase() : "user";

    // Create a new user
    const user = await User.create({
        username: username.trim(),
        email: email.trim(),
        password, 
        role: finalRole,
        isActive: isActive === undefined ? true : isActive, // Safer handling for default value
    });

    const createdUser = await User.findById(user._id).select("-password");
    if (!createdUser) {
        throw new ApiError(500, "User registration failed");
    }

    return res
        .status(201)
        .json(new ApiResponse(201, createdUser, "User registered successfully"));
});

const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email) {
        throw new ApiError(400, "Email is required");
    }

    const userdetail = await User.findOne({ email: email.trim() }); // Correct query format
    if (!userdetail) {
        throw new ApiError(404, "User does not exist");
    }

    const isPasswordvalid = await userdetail.isPasswordCorrect(password);
    if (!isPasswordvalid) {
        throw new ApiError(404, "Invalid Password");
    }

    const accessToken = userdetail.generateAccessToken();

    const options = {
        httpOnly: true,
        secure: true,
    };

    const loggedinUser = await User.findById(userdetail._id).select("-password"); // Removed extra space in select

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .json(new ApiResponse(200, { user: loggedinUser, accessToken }, "User logged in successfully"));
});

const logoutUser = asyncHandler(async (req, res) => {
    const options = {
        httpOnly: true,
        secure: true,
    };
    return res
        .status(200)
        .clearCookie("accessToken", options)
        .json(new ApiResponse(200, {}, "User logged out"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
    if (!req.user) {
        throw new ApiError(404, "User does not exist");
    }
    return res.status(200).json(new ApiResponse(200, req.user, "Current user fetched successfully"));
});

const editRoleAndStatus = asyncHandler(async (req, res) => {
    const { userId } = req.params;
    const { role, status } = req.body;
    const currentUserRole = req.user.role;
    const allowedRolesForAdmin = ["user", "admin", "moderator"];
    const allowedRolesForModerator = ["user", "moderator"];
    const allowedStatuses = [true, false];

    // Ensure at least one of `role` or `status` is provided
    if (!role && status === undefined) {
        throw new ApiError(400, "At least one of `role` or `status` must be provided");
    }

    // Validate `role` if provided
    if (role) {
        const roleList =
            currentUserRole === "admin" ? allowedRolesForAdmin : allowedRolesForModerator;

        if (!roleList.includes(role.toLowerCase())) {
            throw new ApiError(403, "Forbidden: You cannot assign this role");
        }
    }

    // Validate `status` if provided
    if (status !== undefined && !allowedStatuses.includes(status)) {
        throw new ApiError(400, "Invalid status provided. Must be true or false.");
    }

    const user = await User.findById(userId);
    if (!user) {
        throw new ApiError(404, "User not found");
    }

    if (role) user.role = role.toLowerCase();
    if (status !== undefined) user.isActive = status;

    await user.save();

    return res
        .status(200)
        .json(new ApiResponse(200, user, "Role and status updated successfully"));
});

const deleteUser = asyncHandler(async (req, res) => {
    const { userId } = req.params;

    // Validate that the userId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(userId)) {
        throw new ApiError(400, "Invalid User ID");
    }

    // Retrieve the user to be deleted
    const userToDelete = await User.findById(userId);
    if (!userToDelete) {
        throw new ApiError(404, "User not found");
    }

    // Retrieve the current authenticated user (i.e., the user making the request)
    const currentUser = req.user;

    // Check if the user to be deleted is an admin and the current user is not an admin
    if (userToDelete.role === "admin" && currentUser.role !== "admin") {
        throw new ApiError(403, "Only admins can delete other admins");
    }

    // Proceed to delete the user
    await User.findByIdAndDelete(userId);

    return res
        .status(200)
        .json(new ApiResponse(200, { id: userToDelete._id }, "User deleted successfully"));
});

const getAllUsers = asyncHandler(async (req, res) => {
    const { page = 1, limit = 10 } = req.query;

    const users = await User.find({})
        .skip((page - 1) * limit)
        .limit(Number(limit));

    const totalUsers = await User.countDocuments();

    if (users.length === 0) {
        throw new ApiError(404, "No users found");
    }

    const paginationInfo = {
        totalUsers,
        currentPage: Number(page),
        totalPages: Math.ceil(totalUsers / limit),
    };

    return res
        .status(200)
        .json(new ApiResponse(200, { users, paginationInfo }, "Users fetched successfully"));
});

export {
    registerUser,
    loginUser,
    logoutUser,
    editRoleAndStatus,
    deleteUser,
    getAllUsers,
    getCurrentUser
};
