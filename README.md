# Link Shortener

A simple Flask-based URL shortening service with SQLite database persistence and admin panel.

## Features

- **URL Shortening**: Map short codes to full URLs with automatic redirect
- **Role-Based Access Control**: Admin and regular user roles with different permissions
- **User Management**: Admin interface to create, edit, and delete user accounts
- **Admin Panel**: Web interface to add, edit, and delete link mappings
- **User Authentication**: Login system with session management
- **Password Management**: All users can change their own passwords
- **SQLite Database**: Persistent storage for links and user accounts
- **Bootstrap UI**: Clean, responsive web interface
- **Anonymous Redirects**: No authentication required for URL redirections

## Quick Start

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the Application**
   ```bash
   python app.py
   ```

3. **Access the Application**
   - Main site: http://localhost:5000
   - Admin login: http://localhost:5000/admin/login

## Default Admin Credentials

- **Username**: `admin`
- **Password**: `admin`

⚠️ **Important**: Change these credentials in production by updating the database or modifying the `init_db()` function in `app.py`.

## Usage

### For End Users (Anonymous Access)
1. Visit `http://your-domain/shortcode` where `shortcode` is any registered short link
2. You'll be automatically redirected to the target URL
3. No login or authentication required

### For Regular Users
1. Log in to the admin panel at `/admin/login`
2. Access granted to link management only:
   - Add new shortcode/URL pairs
   - Edit or delete existing links
   - Change own password via Profile page
3. Cannot access user management functions

### For Administrators
1. Log in to the admin panel at `/admin/login` 
2. Full access to all functions:
   - Manage all shortcode/URL pairs
   - Create, edit, and delete user accounts
   - Assign admin or regular user roles
   - Change own password
   - View user activity (last login times)

## API Endpoints

### Public Access
- `GET /` - Home page
- `GET /<shortcode>` - Redirect to target URL (anonymous access)

### Authenticated Access (All Users)
- `GET /admin/login` - Login page  
- `POST /admin/login` - Process login
- `GET /admin` - Link management dashboard
- `POST /admin/add` - Add new link
- `POST /admin/edit/<id>` - Edit existing link
- `POST /admin/delete/<id>` - Delete link
- `GET /admin/profile` - User profile page
- `POST /admin/profile/change-password` - Change password
- `GET /admin/logout` - Logout

### Admin Only Access
- `GET /admin/users` - User management dashboard
- `POST /admin/users/add` - Add new user
- `POST /admin/users/edit/<id>` - Edit user account
- `POST /admin/users/delete/<id>` - Delete user account

## Database Schema

### Links Table
- `id` - Primary key
- `shortcode` - Unique short identifier  
- `url` - Target URL
- `created_at` - Timestamp

### Users Table
- `id` - Primary key
- `username` - Unique username
- `password_hash` - Hashed password
- `is_admin` - Boolean flag for admin privileges
- `created_at` - Account creation timestamp
- `last_login` - Last login timestamp

## Configuration

Key settings in `app.py`:
- `app.secret_key` - Change this for production security
- `DATABASE` - SQLite database filename
- `debug=True` - Set to `False` for production

## User Roles & Permissions

### Regular Users
- ✅ Create, edit, delete link shortcuts
- ✅ Change own password
- ❌ Cannot manage other users
- ❌ Cannot access user management

### Admin Users  
- ✅ All regular user permissions
- ✅ Create, edit, delete user accounts
- ✅ Assign user roles (admin/regular)
- ✅ View user activity and login times
- ✅ Full system access

### Anonymous Users
- ✅ Use redirect functionality (no login required)
- ❌ Cannot access any management functions

## Security Notes

- Change the default admin credentials before deployment
- Update the Flask secret key for production use
- Consider using environment variables for sensitive configuration
- Run with a proper WSGI server (not Flask dev server) in production
- All passwords are hashed using Werkzeug's secure password hashing
- Session-based authentication with role-based access control
- Users cannot delete their own accounts or remove their own admin privileges

## File Structure

```
LinkShortener/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── links.db           # SQLite database (created automatically)
├── templates/         # HTML templates
│   ├── base.html      # Base template with navigation
│   ├── index.html     # Home page
│   ├── login.html     # Login page
│   ├── admin.html     # Link management dashboard
│   ├── users.html     # User management page (admin only)
│   ├── profile.html   # User profile and password change
│   └── 404.html       # Not found page
└── README.md          # This file
```
