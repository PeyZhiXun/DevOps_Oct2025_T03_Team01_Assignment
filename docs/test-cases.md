# Test Cases – DevSecOps MVP

## Authentication
| ID | Description | Expected Result |
|----|-------------|-----------------|
| TC-AUTH-01 | User login with valid credentials | Redirect to user dashboard |
| TC-AUTH-02 | Admin login with valid credentials | Redirect to admin dashboard |
| TC-AUTH-03 | Invalid login | Redirect back to login page |
| TC-AUTH-04 | Access dashboard without login | Redirect to login |

## Authorization (Admin)
| ID | Description | Expected Result |
|----|-------------|-----------------|
| TC-ADMIN-01 | Non-admin access /admin | HTTP 403 Forbidden |
| TC-ADMIN-02 | Admin creates new user | User appears in admin list |
| TC-ADMIN-03 | Admin deletes own account | Operation blocked |

## File Management & Data Isolation
| ID | Description | Expected Result |
|----|-------------|-----------------|
| TC-ISO-01 | User uploads file | File visible in own dashboard |
| TC-ISO-02 | User downloads other user's file | Access denied |
| TC-ISO-03 | User deletes other user's file | Operation blocked |
