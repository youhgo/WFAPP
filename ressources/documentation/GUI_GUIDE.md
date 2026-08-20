# WFAPP - Graphical User Interface (GUI) Guide

Welcome to the WFAPP GUI Guide. This document provides a visual and functional overview of the WFAPP Portal, detailing how analysts and administrators can interact with the platform.



---

## 1. Login Page
The secure entry point to the WFAPP Portal.

![Login Page]([../images/login.png])

* **Overview:** 
  * Secures the forensic environment from unauthorized access.
  * Once authenticated, you will be seamlessly redirected to the main dashboard.

---

## 2. Dashboard: File Uploader
The primary interface for submitting and configuring forensic archives for analysis.

![File Uploader]([../images/mainGui.png])

* **Key Features:**
  * **Case Information:** Define the **Case Name** and **Machine Name** which are strictly used to index and group your data in the SIEM (Elasticsearch/Wazuh).
  * **Archive Type:** Select between ORC, KAPE, and UAC. The interface dynamically disables incompatible parsing modules based on your selection.
  * **Module Selection Grid:** Visually toggle specific plugins across 5 phases: Pre-processing, Parsing, Post-processing, Plaso & Derivatives, and SIEM Exports.
  * **Module Help:** Click on "Module Help" to view documentation directly generated from the python backend (including `Recommended` tags).

---

## 3. Dashboard: Log Viewer
Monitor the backend execution of your forensic pipelines.

![Log Viewer]([../images/log_viewer.png])

* **Key Features:**
  * Enter a **Task ID** (provided when you start an analysis) to fetch raw stdout logs.
  * Essential for tracking progress or debugging pipeline errors.

---

## 4. Dashboard: Running Tasks
A global view of what the platform is currently processing.

![Running Tasks]([../images/tasks_status.png])

* **Key Features:**
  * Lists all active and pending tasks running on the infrastructure.
  * Displays the **real-time status** (e.g., `STARTED`, `PENDING`, `SUCCESS`, `FAILURE`) directly on each task card.
  * Displays the **name of the uploaded archive** being processed.
  * Includes a **Kill** button (with a confirmation modal) allowing administrators or users to forcefully interrupt a stuck or erroneous task.

---

## 5. Dashboard: Download DFIR-ORC
Direct access to collection binaries.

![Download DFIR-ORC]([../images/download_orcx.png])

* **Key Features:**
  * **Classic Config:** Standard collection profile.
  * **Offline Mode:** Optimized for endpoint collection without network transmission.
  * **WMemory:** Specific configuration for RAM acquisition.

---

## 6. Profile & Administration
The management hub for user accounts and programmatic API access.

![Profile and Administration]([../images/user_management.png])

* **My Profile (All Users):**
  * View your current role (Standard User / Administrator).
  * Reveal, **Generate**, or **Revoke** your personal API Key for use with external scripts or DFIR-ORC auto-ingestion.
* **User Administration (Admins Only):**
  * Displayed seamlessly below the profile if the user has admin rights.
  * Allows creating new users and deleting existing ones.
  * The **Manage** button opens a modal to forcefully change a user's password, toggle admin rights, or intervene on their API key (including setting a specific custom key).
