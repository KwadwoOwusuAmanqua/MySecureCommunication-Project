# Secure Chat Application - Usage Guide

## Prerequisites
Ensure the project is built. If you haven't built it yet (or if you just pulled updates), run:
```bash
./build.sh
```

## Running the Chat

You need to run the application in **separate terminal windows** to simulate having multiple users.

### Step 1: Start the Host (User A)
1. Open **Terminal 1**.
2. Run the GUI:
   ```bash
   python3 gui_chat.py
   ```
3. **Configure Connection**:
   - **Username**: Enter a name (e.g., `Alice`).
   - **Host Server**: **CHECK** this box.
   - **Port**: `8080` (default).
4. Click **Connect**.
   - This starts the Server and logs `Alice` in.

### Step 2: Start a Client (User B)
1. Open **Terminal 2**.
2. Run the GUI:
   ```bash
   python3 gui_chat.py
   ```
3. **Configure Connection**:
   - **Username**: Enter a different name (e.g., `Bob`).
   - **Host Server**: **UNCHECK** this box.
   - **Server IP**: `127.0.0.1` (or the Host's IP).
   - **Port**: `8080`.
4. Click **Connect**.
   - `Bob` joins the chat.

## Features

### Group Chat (Broadcast)
- Leave the **"To User"** field **EMPTY**.
- Type your message and press **Send** (or Enter).
- Everyone connected will see the message.

### Direct Message (Whisper)
- In the **"To User"** field, type the exact username of the recipient (e.g., `Bob`).
- Type your message and press **Send**.
- Only `Bob` will receive the message.
- You will see `[Whisper to Bob] ...` in your log.
- Bob will see `[Whisper from Alice] ...` in his log.

### Key Rotation
- Click **"Rotate Key"** to manually trigger a session key rotation for added security.
