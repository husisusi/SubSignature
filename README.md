<h1>
  <img src="https://raw.githubusercontent.com/husisusi/SubSignature/main/public_html/img/subsig_logo.png"
       alt="SubSignature Logo"
       height="100"
       style="vertical-align: middle;">
  SubSignature
</h1>

![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4?style=flat-square&logo=php&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=flat-square&logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

SubSignature is a lightweight, self-hosted email signature generator built with PHP and SQLite. It was designed to help organizations manage and standardize email signatures without relying on complex database setups or paid cloud services.

The primary focus of this project is privacy and security. The application runs entirely offline within your server environment, meaning no external requests to CDNs (like Cloudflare or Google Fonts) are made by the client. All assets are hosted locally.

## Screenshots

**Generator Interface**
![Generator Interface](https://raw.githubusercontent.com/husisusi/SubSignature/main/public_html/img/screenshots/SubSignature_screenshot_generator.png)

**User Management**
![User Management](https://raw.githubusercontent.com/husisusi/SubSignature/main/public_html/img/screenshots/SubSignature_screenshot_user.png)

**Template Editor**
![Template Editor](https://raw.githubusercontent.com/husisusi/SubSignature/main/public_html/img/screenshots/SubSignature_screenshot_editor.png)

**Import CSV**
![Import Function](https://raw.githubusercontent.com/husisusi/SubSignature/main/public_html/img/screenshots/SubSignature_screenshot_import.png)

## Features
* **Create professional signatures** Create consistent, professional email signatures that reflect your brand identity and stay up to date automatically.
* **Multiple design templates** Choose from a variety of ready-made design templates that can be easily customized for different teams or use cases.
* **Secure user management** Manage user accounts centrally with secure role-based access control and high data protection standards.
* **Account activation system** Activate user accounts through a secure activation process.
* **Self-Hosted & Private:** Runs on your own server. No data is sent to third parties.
* **Database:** Uses SQLite. No MySQL or PostgreSQL configuration required.
* **Role-Based Access:**
    * **Admins:** Can create templates, manage users, view system logs, and import/export data.
    * **Users:** Can log in and generate their own signatures based on approved templates.
* **Visual Editor:** Integrated WYSIWYG editor for designing HTML signatures.
* **Security:** Includes brute-force protection, rate limiting, and comprehensive audit logs.
* **Data Management:** Support for CSV import and export of user signatures.

## Installation

1.  Upload the files to your web server (tested with Apache 2).
2.  Ensure the `private_data` folder is located one level above your public web directory (for security reasons) and is writable by the web server.
3.  Navigate to `install.php` in your browser to initialize the SQLite database and create your admin account.
4.  Delete `install.php` after the setup is complete.

## Credits & Third-Party Assets

This project makes use of excellent open-source libraries and resources:

* **Jodit Editor:** The template creation interface is powered by the Jodit WYSIWYG editor. It provides a clean and powerful interface for editing HTML directly in the browser.
* **Ace Editor:** Standalone code editor written in JavaScript.
* **Free Icons:** User interface icons are provided by FontAwesome (Free tier), hosted locally to ensure privacy compliance.

## Contributing

This project is a work in progress, and I am always looking for ways to improve it.

If you have ideas for new features, find a security issue, or want to improve the code, your help is welcome. Please feel free to open an issue or submit a pull request.

## ToDo
LDAP integration.
