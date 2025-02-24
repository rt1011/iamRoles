import asyncio
from pyppeteer import launch

async def get_saml_assertion():
    """Logs in to Azure AD and extracts the SAML assertion (SAMLResponse)."""
    browser = await launch(headless=True, args=["--no-sandbox"])
    page = await browser.newPage()

    IDP_LOGIN_URL = "https://login.microsoftonline.com/YOUR-TENANT-ID/saml2"
    await page.goto(IDP_LOGIN_URL, {"waitUntil": "networkidle2"})

    # Step 1: Enter Username
    await page.type("#i0116", "your-email@example.com")
    await page.keyboard.press("Enter")
    await asyncio.sleep(2)

    # Step 2: Enter Password
    await page.type("#i0118", "your-password")
    await page.keyboard.press("Enter")
    await asyncio.sleep(5)

    # Step 3: Wait for MFA Approval (if needed)
    input("🔹 Approve MFA and press Enter to continue...")

    # Step 4: Extract SAML Assertion
    saml_assertion = await page.evaluate('''() => {
        let samlInput = document.querySelector("input[name='SAMLResponse']");
        return samlInput ? samlInput.value : null;
    }''')

    await browser.close()

    return saml_assertion

if __name__ == "__main__":
    saml_assertion = asyncio.run(get_saml_assertion())
    if saml_assertion:
        print("\n✅ SAML Assertion Extracted:\n", saml_assertion[:100] + "... (truncated)")
    else:
        print("\n❌ Failed to retrieve SAML assertion.")
