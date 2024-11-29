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
