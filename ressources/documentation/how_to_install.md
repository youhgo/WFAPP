# Windows Artefact Parser Project - Installation Guide ⚙️

This guide will walk you through the simple process of setting up WAPP using Docker.

---

## 🔗 Useful Links

* **WAPP Repository:** <https://github.com/youhgo/WFAPP>
* **Usage Tutorial:** <https://youhgo.github.io/DOPP-how-to-use-EN/>
* **Results Architecture:** <https://youhgo.github.io/DOPP-Results/>

---

## 📋 Prerequisites

You need to have Docker and Docker Compose installed on your system.

### Option 1: Using Official Guides (Recommended)

* **Install Docker:** Follow the official guide [here](https://docs.docker.com/engine/install/).
* **Install Docker Compose:** Follow the official guide [here](https://docs.docker.com/compose/install/linux/#install-using-the-repository).

### Option 2: Using Command-Line Snippets

For a quick installation on Ubuntu-based systems, you can run the following commands.

```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL [https://download.docker.com/linux/ubuntu/gpg](https://download.docker.com/linux/ubuntu/gpg) -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] [https://download.docker.com/linux/ubuntu](https://download.docker.com/linux/ubuntu)  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

```

---

## ⬇️ Download WAPP

Clone the repository to your local machine:

`git clone https://github.com/youhgo/WFAPP`

---

## 🔧 Configure Shared Volume

To share results with other analysts, you need to create a shared volume between your host machine and the Docker containers.

1.  Edit the `docker-compose.yml` file.
2.  Locate the `volumes` variable under the `wappApi` and `wappWorker` sections. **Do not** modify any other `volumes` variables.
3.  Change the path to your desired shared directory.

For example on my machine:

**Before:**
```yml
volumes:
  - /please/change/me/shared:/python-docker/shared_files/
```

**After:**
```yml
volumes:
  - /home/hro/Documents/working_zone/shared:/python-docker/shared_files/
```

This change means all files in `/home/hro/Documents/working_zone/shared/` on your machine will be accessible by Docker.
Every output from WAPP will be written is this directory and subdirectories.

---

## ▶️ Build and Run

From the WAPP directory, run the following command to build and launch the entire application:

`docker compose up --build`

### Verification

Once the build is complete, you can verify that the tool is running by making a simple `curl` request:

`curl -X GET -k https://wapp.localhost/ | jq`

If successful, you will receive a response like this:
```json
{
"message": "Welcom to Windows Forensic Artefact Parser Project",
"serveurTime": "02/05/2024 02:06:33",
"status": "OK"
}
```

Congratulations, WAPP is now ready to go!