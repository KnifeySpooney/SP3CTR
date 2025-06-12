# SP3CTR - Quick Start Guide

Thank you for trying SP3CTR (pronounced "specter")! This guide will help you get the application running.

## Prerequisites

1.  **Python 3:** Ensure you have Python installed on your system.
2.  **Npcap:** For packet sniffing on Windows, Npcap must be installed. If you haven't installed it, you can get it from the [official Npcap website](https://npcap.com/#download). It's recommended to select the "WinPcap API-compatible Mode" during installation.

## Installation

Before running for the first time, you need to install the required Python libraries.

1.  **Open a Command Prompt or PowerShell** in this folder (you can often do this by Shift + Right-clicking in the folder and choosing "Open PowerShell window here").
2.  Run the following command to install the dependencies:
    ```
    pip install -r requirements.txt
    ```
    *(Note: If you have multiple Python versions, you might need to use `python -m pip install -r requirements.txt` or `py -m pip install -r requirements.txt`)*

## How to Run SP3CTR

1.  **Run with Administrator Privileges:** The packet capture functionality requires elevated permissions. Right-click on the `run_sp3ctr.py`  launcher script and select **"Run as administrator"**.

2.  **Use the Launcher Script:** Simply execute the launcher script provided:
    * `run_sp3ctr.py` (for the Python-based launcher)

3.  The script will automatically:
    * Start the SP3CTR backend server.
    * Start a local web server for the user interface.
    * Open SP3CTR in your default web browser.

## How to Stop SP3CTR

To shut down the application, simply **close the two new black console windows** that were opened by the launcher script (one for the "Backend" and one for the "Frontend Server").

---
Enjoy exploring your network!

