import { Router } from 'express';
import { registerUser,
    loginUser,
    logoutUser,
    editRoleAndStatus,
    deleteUser,
    getAllUsers,
    getCurrentUser } from '../contoller/user.controller.js';

import { verifyJWT , verifyAuthentication , ensureSingleAdmin } from '../middlewwares/auth.middleware.js';

const router = Router(); 

// Register a new user - Ensure only one admin exists
router.route("/register").post(ensureSingleAdmin, registerUser);

// User login
router.route("/login").post(loginUser);

// User logout (requires JWT verification)
router.route("/logout").post(verifyJWT, logoutUser);

// Get current logged-in user details (requires JWT verification)
router.route('/current-user').get(verifyJWT, getCurrentUser);

// Edit user's role and status (requires authentication)
router.route('/edit-role-status/:userId').put(verifyAuthentication, editRoleAndStatus);  // More descriptive route

// Delete a user listing by user ID (requires authentication)
router.route('/deleteUserListing/:userId').delete(verifyAuthentication, deleteUser);

// Get all users (requires JWT verification)
router.route('/all-users').get(verifyJWT, getAllUsers); 

export default router;