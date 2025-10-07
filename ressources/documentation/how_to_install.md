# Artefact Parser Project - Installation Guide ⚙️

This guide will walk you through the simple process of setting up APP using Docker.

---

## 🔗 Useful Links

* **APP Repository:** [Available here](https://github.com/youhgo/WFAPP)
* **Configuration Tutorial:** [Configuration Tutorial](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/Configure_WAPP.md)
* **Usage Tutorial:** [Usage Tutorial](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/how_to_use.md)
* **Results Architecture:** [Explained here](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/Explaining_the_results.md)
* **DFIR-ORC Configuration:** [Tutorial](https://github.com/youhgo/WFAPP/blob/master/ressources/documentation/configure_orc.md)
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

## ⬇️ Download APP

Clone the repository to your local machine:

`git clone https://github.com/youhgo/WFAPP`

---

## NOTE

It is highly recommended to follow [this guide](./Configure_WAPP.md) if you don't plan to use the pre-configured DFIR-Orc.exe collection tool.

## 🔧 Configure 

To share results with other analysts, you need to create a shared volume between your host machine and the Docker containers.

1.  Edit the `.env` file.
2.  Locate the `WAPP_API_HOST` variable and modify it to the hostname you want the app to be accessible to
3.  Locate the `SHARED_FOLDER_PATH` and change the path to your desired shared directory.
4.  Edit the information for ELK and SPLUNK

For example on my machine:

```env
ELK_HOST=192.168.1.19
ELK_PORT=9200
ELK_USER="elastic"
ELK_PASSWD="changeme"
WAPP_API_HOST=wapp.localhost
SHARED_FOLDER_PATH=/home/hro/Documents/shared
```

This change means all files in `/home/hro/Documents/working_zone/shared/` on your machine will be accessible by Docker.
Every output from APP will be written is this directory and subdirectories.

---

## ▶️ Build and Run

From the APP directory, run the following command to build and launch the entire application:

`docker compose build`

### Verification

Once the build is complete, you can verify that the tool is running by making a simple `curl` request:

`docker compose up`
then 
`curl -X GET -k https://wapp.localhost/ | jq`

If successful, you will receive a response like this:
```json
{
"message": "Welcome to Forensic Artefact Parser Project",
"serveurTime": "02/05/2025 02:06:33",
"status": "OK"
}
```

Congratulations, APP is now ready to go!

Note : you can set up multiple workers using the docker compose scale option, for 3 celery workers:

`docker-compose up -d --scale wapp_worker=3`