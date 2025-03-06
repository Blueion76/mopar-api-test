import asyncio
import requests
import logging
import json
import re
from typing import Dict, List, Union
from urllib.parse import urlencode, urljoin
import time

# Set up logging
logging.basicConfig(level=logging.DEBUG)
_LOGGER = logging.getLogger("test_mopar")

# Mopar session
mopar_session = requests.Session()

# Constants (updated for current date and requirements)
MOPAR_BASE_URL = "https://www.mopar.com"
SSO_URL = "https://sso.extra.chrysler.com/siteminderagent/forms/b2clogin.fcc"
TARGET_URL = "https://sso.extra.chrysler.com/cgi-bin/moparproderedirect.cgi?env=prd&PartnerSpId=B2CAEM&IdpAdapterId=B2CSM&appID=MOPUSEN_C&TargetResource=" + MOPAR_BASE_URL + "/sign-in"
SIGNIN_URL = MOPAR_BASE_URL + "/sign-in"
DASHBOARD_URL = MOPAR_BASE_URL + "/jeep/en-us/my-vehicle/dashboard.html"
GET_VEHICLES_URL = MOPAR_BASE_URL + "/moparsvc/user/getVehicles"

# Headers (updated to match browser HAR - Windows, as per HAR for consistency)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"

def set_mopar_session_defaults():
    mopar_session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1",
        "Sec-GPC": "1",
        "Sec-Ch-Ua": "\"Not(A:Brand\";v=\"99\", \"Brave\";v=\"133\", \"Chromium\";v=\"133\"",
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site"
    })

class MoparError(Exception):
    """Mopar error."""
    pass

def update_cookies(response) -> None:
    if 'set-cookie' in response.headers:
        mopar_session.cookies.update(response.cookies)
    _LOGGER.debug("Cookies updated")

async def sign_in(max_attempts: int = 3) -> bool:
    attempt = 1
    while attempt <= max_attempts:
        try:
            # Prompt for credentials
            email = input("Enter your Mopar email: ").strip()
            if not email:
                raise MoparError("Email cannot be empty")
            
            password = input("Enter your Mopar password: ").strip()
            if not password:
                raise MoparError("Password cannot be empty")

            _LOGGER.info("Logging in using SAML (no valid session found)")
            mopar_session.cookies.clear()

            # Step 1: Post credentials to SSO URL
            payload = {'USER': email, 'PASSWORD': password, 'TARGET': TARGET_URL}
            headers = mopar_session.headers.copy()
            headers['Content-Type'] = "application/x-www-form-urlencoded"
            headers['Referer'] = MOPAR_BASE_URL
            headers['Sec-Fetch-Site'] = "cross-site"
            res1 = mopar_session.post(SSO_URL, data=payload, headers=headers, allow_redirects=True)
            res1.raise_for_status()
            _LOGGER.debug(f"Step 1 - SSO response received")
            update_cookies(res1)

            # Check for invalid credentials
            if "/invalid-password.html" in res1.url:
                _LOGGER.error(f"Attempt {attempt}: Invalid credentials detected")
                if attempt < max_attempts:
                    attempt += 1
                    continue
                raise MoparError("Invalid credentials after maximum attempts")

            # Step 2: Post SAML to sign-in URL if needed
            if not res1.url.startswith(MOPAR_BASE_URL):
                saml_form_pattern = r'<input[^>]*name=["\']SAMLResponse["\'][^>]*value=["\'](.*?)["\']'
                relay_state_pattern = r'<input[^>]*name=["\']RelayState["\'][^>]*value=["\'](.*?)["\']'
                saml_match = re.search(saml_form_pattern, res1.text)
                relay_match = re.search(relay_state_pattern, res1.text)
                
                if saml_match and relay_match:
                    saml_response_value = saml_match.group(1)
                    relay_state_value = relay_match.group(1)
                    
                    payload2 = {'RelayState': relay_state_value, 'SAMLResponse': saml_response_value}
                    headers['Referer'] = res1.url
                    headers['Sec-Fetch-Site'] = "same-origin"
                    res2 = mopar_session.post(SIGNIN_URL, data=payload2, headers=headers, allow_redirects=True)
                    res2.raise_for_status()
                    _LOGGER.debug("Step 2 - Sign-in response received")
                    update_cookies(res2)

                    if "/invalid-password.html" in res2.url:
                        _LOGGER.error(f"Attempt {attempt}: Invalid credentials detected after SAML")
                        if attempt < max_attempts:
                            attempt += 1
                            continue
                        raise MoparError("Invalid credentials after maximum attempts")
                else:
                    _LOGGER.warning("No SAML form found—proceeding with cookies to sign-in")
                    headers['Referer'] = res1.url
                    res2 = mopar_session.get(SIGNIN_URL, headers=headers, allow_redirects=True)
                    res2.raise_for_status()
                    _LOGGER.debug("Step 2 - Direct sign-in response received")
                    update_cookies(res2)

                    if "/invalid-password.html" in res2.url:
                        _LOGGER.error(f"Attempt {attempt}: Invalid credentials detected in direct sign-in")
                        if attempt < max_attempts:
                            attempt += 1
                            continue
                        raise MoparError("Invalid credentials after maximum attempts")

            # Step 3: Verify session with dashboard
            headers['Referer'] = SIGNIN_URL
            res3 = mopar_session.get(DASHBOARD_URL, headers=headers, allow_redirects=True)
            res3.raise_for_status()
            _LOGGER.debug("Step 3 - Dashboard response received")
            update_cookies(res3)

            if "/sign-in" in res3.url:
                raise MoparError("Login failed - Redirected to sign-in page")

            # Additional dashboard fetch to ensure full session initialization
            time.sleep(1)
            res4 = mopar_session.get(DASHBOARD_URL, headers=headers, allow_redirects=True)
            res4.raise_for_status()
            _LOGGER.debug("Step 4 - Additional dashboard response received")
            update_cookies(res4)

            # Final verification
            if res4.status_code == 200 and 'dashboard' in res4.url and "/sign-in" not in res4.url:
                _LOGGER.info("SAML login successful - Dashboard access confirmed")
                return True
            else:
                raise MoparError("Login failed - Dashboard access not confirmed")
        except requests.exceptions.RequestException as e:
            _LOGGER.error(f"Login failed (attempt {attempt}): {str(e)}")
            if attempt < max_attempts:
                attempt += 1
                continue
            return False

async def sign_out() -> str:
    try:
        sign_out_url = urljoin(MOPAR_BASE_URL, "sign-out")
        headers = mopar_session.headers.copy()
        res = mopar_session.post(sign_out_url, headers=headers)
        res.raise_for_status()
        mopar_session.cookies.clear()
        _LOGGER.debug("Sign-out request completed")
        return ""
    except requests.exceptions.RequestException as e:
        return str(e) if isinstance(e, requests.exceptions.RequestException) else "An unexpected error occurred"

async def get_vehicle_data() -> Union[List[Dict], str]:
    try:
        headers = mopar_session.headers.copy()
        headers.update({
            'Accept': "application/json, text/javascript, */*; q=0.01",
            'Sec-Fetch-Dest': "empty",
            'Sec-Fetch-Mode': "cors",
            'Sec-Fetch-Site': "same-origin",
            'X-Requested-With': "XMLHttpRequest",
            'DNT': "1",
            'Sec-GPC': "1"
        })

        # First attempt
        _LOGGER.debug("Sending first GET to get vehicle data")
        res1 = mopar_session.get(GET_VEHICLES_URL, headers=headers)
        res1.raise_for_status()
        data1 = res1.json()
        _LOGGER.debug("First vehicles response received")

        # If empty, log a warning but continue
        if not data1 or data1 == []:
            _LOGGER.warning("Vehicle API returned empty list - user may have no vehicles associated")

        # If 403, retry after a short delay
        if 'errorCode' in data1 and data1['errorCode'] == '403':
            _LOGGER.warning("First getVehicles call returned 403, retrying...")
            time.sleep(2)
            _LOGGER.debug("Sending second GET to get vehicle data")
            res2 = mopar_session.get(GET_VEHICLES_URL, headers=headers)
            res2.raise_for_status()
            data2 = res2.json()
            _LOGGER.debug("Second vehicles response received")
            update_cookies(res2)
            return data2
        else:
            update_cookies(res1)
            return data1
    except requests.exceptions.RequestException as e:
        return str(e) if isinstance(e, requests.exceptions.RequestException) else "An unexpected error occurred"

async def main():
    try:
        # Set headers
        set_mopar_session_defaults()

        # Sign in and verify login
        if await sign_in():
            _LOGGER.info("Successfully signed in")

            # Test session by fetching vehicle data via API
            vehicle_data = await get_vehicle_data()
            if isinstance(vehicle_data, str):
                _LOGGER.error(f"Failed to get vehicle data: {vehicle_data}")
            else:
                _LOGGER.info("Vehicle data retrieved")
                if vehicle_data == []:
                    _LOGGER.info("API call succeeded with empty list - login confirmed, but no vehicles associated")
                else:
                    _LOGGER.info("API call succeeded with vehicle data - login confirmed")

            # Sign out
            sign_out_result = await sign_out()
            if sign_out_result:
                _LOGGER.error(f"Sign out failed: {sign_out_result}")
            else:
                _LOGGER.info("Successfully signed out")
        else:
            _LOGGER.error("Sign in failed")
    except Exception as e:
        _LOGGER.error(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
