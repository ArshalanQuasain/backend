# User Management Backend

This backend application is built using Node.js and Express.js. It provides functionality for managing users, including registration, authentication, and role-based access control. The application ensures secure handling of user data, supports CRUD operations, and enforces business rules like limiting the number of admin users.

---

## Features

### 1. **User Registration**
- Allows users to register with roles such as `user` or `admin`.
- Ensures there can be only one `admin` during the registration process.
- Validates required fields (`username`, `email`, and `password`) and ensures unique usernames and emails.

### 2. **User Login**
- Authenticates users using their email and password.
- Generates a secure JWT token upon successful login.
- Stores the token in an HTTP-only cookie to prevent XSS attacks.

### 3. **User Logout**
- Clears the JWT token from cookies to log the user out securely.

### 4. **Role and Status Management**
- Allows modification of a user's `role` and `isActive` status.
- Restricts changes based on the current user's role:
  - Admins can assign any role (`user`, `admin`, `moderator`).
  - Moderators can assign only `user` or `moderator`.

### 5. **Delete Users**
- Deletes a user based on their ID.
- Ensures only `admin` users can delete other admins.

### 6. **Get Current User**
- Retrieves the details of the currently logged-in user using the JWT token.

### 7. **Fetch All Users**
- Fetches a paginated list of all registered users.
- Includes details like total users, current page, and total pages.

---

## Technologies Used

- **Node.js**: JavaScript runtime environment.
- **Express.js**: Backend framework for building APIs.
- **MongoDB**: Database for storing user information.
- **Mongoose**: ODM for MongoDB, used for schema definition and queries.
- **JWT**: For secure user authentication.
- **bcrypt**: For password hashing.
- **dotenv**: For managing environment variables.

---

## Installation

1. Clone the repository:
   ```bash
   git clone <https://github.com/ArshalanQuasain/backend.git>
   cd <repository-folder>

## API Endpoints

### Base URL: `/api/v1`

| **HTTP Method** | **Endpoint**                   | **Description**                          | **Middleware**          |
|------------------|--------------------------------|------------------------------------------|-------------------------|
| POST             | `/register`                   | Register a new user.                     | `ensureSingleAdmin`     |
| POST             | `/login`                      | Log in an existing user.                 | None                    |
| POST             | `/logout`                     | Log out the current user.                | `verifyJWT`             |
| GET              | `/current-user`               | Get the details of the logged-in user.   | `verifyJWT`             |
| PUT              | `/edit-role-status/:userId`   | Edit a user's role and status.           | `verifyAuthentication`  |
| DELETE           | `/deleteUserListing/:userId`  | Delete a user by ID.                     | `verifyAuthentication`  |
| GET              | `/all-users`                  | Fetch a paginated list of users.         | `verifyJWT`             |


## User Schema

Defines the structure for storing user data in MongoDB.

| **Field**   | **Type**   | **Description**                             |
|-------------|------------|---------------------------------------------|
| `username`  | `String`   | Unique username for the user.               |
| `email`     | `String`   | Unique email address for the user.          |
| `password`  | `String`   | Hashed password for secure storage.         |
| `isActive`  | `Boolean`  | Indicates if the user's account is active.  |
| `role`      | `String`   | Role of the user (`admin`, `moderator`, `user`). |

---

### Pre-save Hook
- Hashes the password using `bcrypt` before saving it.

---

### Methods

1. **`isPasswordCorrect`**
   - Compares a plain-text password with the hashed password.

2. **`generateAccessToken`**
   - Generates a JWT token with user details.


## Folder Structure

```bash
project/
├── controller/
│   └── user.controller.js      # Handles API logic for user routes
├── middlewares/
│   └── auth.middleware.js      # Authentication and role-based access control
├── model/
│   └── user.model.js           # Defines the User schema and methods
├── routes/
│   └── user.routes.js          # Defines API endpoints and middleware
├── utils/
│   ├── apiresponse.js          # Utility for consistent API responses
│   ├── apperror.js             # Custom error class for handling exceptions
│   └── assynchandler.js        # Utility for wrapping async functions
├── .env                        # Environment variables (ignored in Git)
├── app.js                      # Initializes and configures the Express app
└── server.js                   # Entry point for the application
