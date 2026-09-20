// Netlify Edge Function: Server-Enforced Authentication & Lobby Gate
// Runtime: Deno Edge Environment

const SALT = ":decks_bauhaus_vault_secret_2026";
const DEFAULT_PASSWORD = "decks2026";

async function computeExpectedToken(password) {
    const data = new TextEncoder().encode(password + SALT);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(hashBuffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function parseCookies(cookieHeader) {
    const cookies = {};
    if (!cookieHeader) return cookies;
    cookieHeader.split(";").forEach(cookie => {
        const parts = cookie.split("=");
        if (parts.length >= 2) {
            const key = parts[0].trim();
            const val = parts.slice(1).join("=").trim();
            cookies[key] = decodeURIComponent(val);
        }
    });
    return cookies;
}

export default async function handler(request, context) {
    const url = new URL(request.url);
    const configuredPassword = Deno.env.get("ADMIN_PASSWORD") || DEFAULT_PASSWORD;
    const expectedToken = await computeExpectedToken(configuredPassword);

    const cookieHeader = request.headers.get("cookie") || "";
    const cookies = parseCookies(cookieHeader);
    const sessionToken = cookies["deck_session"];
    const isAuthenticated = (sessionToken === expectedToken);

    // 1. API: Login
    if (url.pathname === "/api/login" && request.method === "POST") {
        try {
            let providedPassword = "";
            const contentType = request.headers.get("content-type") || "";
            if (contentType.includes("application/json")) {
                const body = await request.json();
                providedPassword = body.password || "";
            } else if (contentType.includes("application/x-www-form-urlencoded") || contentType.includes("multipart/form-data")) {
                const formData = await request.formData();
                providedPassword = formData.get("password") || "";
            }

            if (providedPassword === configuredPassword) {
                const isSecure = url.protocol === "https:";
                const secureFlag = isSecure ? "Secure;" : "";
                const cookieStr = `deck_session=${expectedToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000; ${secureFlag}`;

                return new Response(JSON.stringify({ success: true, message: "Authenticated successfully" }), {
                    status: 200,
                    headers: {
                        "Content-Type": "application/json",
                        "Set-Cookie": cookieStr
                    }
                });
            } else {
                return new Response(JSON.stringify({ success: false, error: "Invalid password" }), {
                    status: 401,
                    headers: { "Content-Type": "application/json" }
                });
            }
        } catch (err) {
            return new Response(JSON.stringify({ success: false, error: "Bad request payload" }), {
                status: 400,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    // 2. API: Auth Status Check (Called by Slide Decks to verify edit permission)
    if (url.pathname === "/api/auth-status") {
        return new Response(JSON.stringify({ authenticated: isAuthenticated }), {
            status: 200,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-store, no-cache, must-revalidate"
            }
        });
    }

    // 3. API: Logout
    if (url.pathname === "/api/logout") {
        const isSecure = url.protocol === "https:";
        const secureFlag = isSecure ? "Secure;" : "";
        const cookieStr = `deck_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; ${secureFlag}`;

        if (request.method === "POST" || request.headers.get("accept")?.includes("application/json")) {
            return new Response(JSON.stringify({ success: true, message: "Logged out" }), {
                status: 200,
                headers: {
                    "Content-Type": "application/json",
                    "Set-Cookie": cookieStr
                }
            });
        } else {
            return new Response(null, {
                status: 302,
                headers: {
                    "Location": "/",
                    "Set-Cookie": cookieStr
                }
            });
        }
    }

    // 4. Main Lobby Protection: "/" and "/index.html"
    if (url.pathname === "/" || url.pathname === "/index.html") {
        if (isAuthenticated) {
            // Forward directly to the Bauhaus lobby HTML
            return context.next();
        } else {
            // Render the Bauhaus Master Access Gate
            return new Response(renderLoginPage(), {
                status: 200,
                headers: {
                    "Content-Type": "text/html; charset=utf-8",
                    "Cache-Control": "no-store, no-cache, must-revalidate"
                }
            });
        }
    }

    // For all other routes (slide presentations, assets), pass through
    return context.next();
}

function renderLoginPage() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Master Access &mdash; Slides Directory</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #F0F0F0;
            --fg: #121212;
            --border: #121212;
            --yellow: #F0C020;
            --red: #D02020;
            --blue: #1040C0;
            --white: #FFFFFF;
            --font-main: 'Outfit', -apple-system, sans-serif;
            --border-w: 3px;
            --shadow-hard: 6px 6px 0px 0px #121212;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            border-radius: 0px !important;
        }

        body {
            background-color: var(--bg);
            color: var(--fg);
            font-family: var(--font-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            -webkit-font-smoothing: antialiased;
        }

        .login-card {
            width: 100%;
            max-width: 440px;
            background: var(--white);
            border: var(--border-w) solid var(--border);
            box-shadow: var(--shadow-hard);
            display: flex;
            flex-direction: column;
            animation: cardAppear 0.25s cubic-bezier(0.16, 1, 0.3, 1);
        }

        @keyframes cardAppear {
            from { opacity: 0; transform: translateY(16px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .card-header {
            background: var(--fg);
            color: var(--white);
            padding: 18px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .header-title {
            font-size: 16px;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .status-dot {
            width: 10px;
            height: 10px;
            background: var(--yellow);
            display: inline-block;
        }

        .card-body {
            padding: 32px 28px 24px;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        .prompt-text {
            font-size: 14px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: #555;
            line-height: 1.4;
        }

        .input-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .input-label {
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--fg);
        }

        .input-field {
            width: 100%;
            padding: 14px 16px;
            font-family: var(--font-main);
            font-size: 16px;
            font-weight: 700;
            color: var(--fg);
            background: #FAFAFA;
            border: var(--border-w) solid var(--border);
            outline: none;
            transition: background-color 0.15s ease, border-color 0.15s ease;
        }

        .input-field:focus {
            background: #FFF;
            border-color: var(--blue);
        }

        .input-field.error {
            border-color: var(--red);
            background: #FFF5F5;
            animation: shake 0.3s ease;
        }

        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            20%, 60% { transform: translateX(-6px); }
            40%, 80% { transform: translateX(6px); }
        }

        .error-banner {
            display: none;
            background: var(--red);
            color: var(--white);
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 10px 14px;
        }

        .btn-unlock {
            width: 100%;
            padding: 16px;
            background: var(--yellow);
            color: var(--fg);
            font-family: var(--font-main);
            font-size: 14px;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            border: var(--border-w) solid var(--border);
            box-shadow: 4px 4px 0px 0px #121212;
            cursor: pointer;
            transition: transform 0.05s ease, box-shadow 0.05s ease, background-color 0.1s ease;
            user-select: none;
        }

        .btn-unlock:hover {
            background: #FFD84D;
            transform: translate(-1px, -1px);
            box-shadow: 5px 5px 0px 0px #121212;
        }

        .btn-unlock:active {
            transform: translate(2px, 2px);
            box-shadow: none;
        }

        .btn-unlock:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            box-shadow: none;
        }

        .card-footer {
            border-top: var(--border-w) solid var(--border);
            background: #EFEFEF;
            padding: 12px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #666;
        }
    </style>
</head>
<body>

    <div class="login-card">
        <div class="card-header">
            <span class="header-title"><span class="status-dot"></span> Vault Access</span>
            <span style="font-size:11px; font-weight:700; letter-spacing:0.06em; opacity:0.8;">ENCRYPTED GATE</span>
        </div>

        <div class="card-body">
            <p class="prompt-text">Enter your Master Password to access the presentation directory and management tools.</p>

            <div class="input-group">
                <label class="input-label" for="masterPassword">Master Password</label>
                <input type="password" id="masterPassword" class="input-field" placeholder="Enter password..." autocomplete="current-password" autofocus>
            </div>

            <div class="error-banner" id="errorBanner">Invalid master password. Access denied.</div>

            <button class="btn-unlock" id="unlockBtn" onclick="submitLogin()">[ Unlock Directory ]</button>
        </div>

        <div class="card-footer">
            <span>Server-Enforced Auth</span>
            <span>Netlify Edge Security</span>
        </div>
    </div>

    <script>
        const input = document.getElementById('masterPassword');
        const btn = document.getElementById('unlockBtn');
        const errBanner = document.getElementById('errorBanner');

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') submitLogin();
        });

        async function submitLogin() {
            const password = input.value.trim();
            if (!password) {
                input.focus();
                return;
            }

            btn.disabled = true;
            btn.innerText = "AUTHENTICATING...";
            errBanner.style.display = "none";
            input.classList.remove('error');

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });

                const data = await res.json();
                if (res.ok && data.success) {
                    btn.innerText = "✓ UNLOCKED — LOADING...";
                    btn.style.background = "#4ADE80";
                    setTimeout(() => {
                        window.location.reload();
                    }, 250);
                } else {
                    input.classList.add('error');
                    errBanner.style.display = "block";
                    errBanner.innerText = data.error || "Invalid master password. Access denied.";
                    btn.disabled = false;
                    btn.innerText = "[ Unlock Directory ]";
                    input.select();
                }
            } catch (err) {
                input.classList.add('error');
                errBanner.style.display = "block";
                errBanner.innerText = "Connection error. Please try again.";
                btn.disabled = false;
                btn.innerText = "[ Unlock Directory ]";
            }
        }
    </script>
</body>
</html>`;
}
