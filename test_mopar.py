import asyncio
import requests
import logging
import json
import re
from bs4 import BeautifulSoup
from typing import Dict, List, Union
from urllib.parse import urlencode, urljoin
import time
import random

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
LOADING_URL = MOPAR_BASE_URL + "/en-us/loading.html"
DASHBOARD_URL = MOPAR_BASE_URL + "/dodge/en-us/my-vehicle/dashboard.html"
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
        "Sec-GPC": "1",  # Added from HAR
        "Sec-Ch-Ua": "\"Not(A:Brand\";v=\"99\", \"Brave\";v=\"133\", \"Chromium\";v=\"133\"",
        "Sec-Ch-Ua-Mobile": "?0",  # Updated to match Windows
        "Sec-Ch-Ua-Platform": "\"Windows\"",  # Updated to match Windows
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site"
    })

class MoparError(Exception):
    """Mopar error."""
    pass

def create_cookie(cookies: dict) -> str:
    return "; ".join(f"{key}={value}" for key, value in cookies.items())

def update_cookies(response) -> None:
    if 'set-cookie' in response.headers:
        mopar_session.cookies.update(response.cookies)
    _LOGGER.debug(f"Updated cookies: {mopar_session.cookies.get_dict()}")

def parse_cookies(cookies: Union[str, list, None]) -> dict:
    cookie_obj = {}
    pattern = r"(?P<key>\w+)=(?P<value>[^;]+)(?:;?)"
    if isinstance(cookies, str):
        cookies = cookies.split("; ")
    for cookie in cookies or []:
        match = re.match(pattern, cookie)
        if match and match.group('key') and match.group('value'):
            cookie_obj[match.group('key')] = match.group('value')
    return cookie_obj

async def sign_in(max_attempts: int = 3) -> bool:
    attempt = 1
    while attempt <= max_attempts:
        try:
            # Prompt for credentials (no hardcoded values)
            email = input("Enter your Mopar email: ").strip()
            if not email:
                raise MoparError("Email cannot be empty")
            
            password = input("Enter your Mopar password: ").strip()
            if not password:
                raise MoparError("Password cannot be empty")

            _LOGGER.info("Logging in using SAML (no valid session found)")
            mopar_session.cookies.clear()

            # Step 1: Post credentials to SSO URL, allowing redirects
            payload = {
                'USER': email,
                'PASSWORD': password,  # No quote() needed here, as per working code
                'TARGET': TARGET_URL
            }
            headers = mopar_session.headers.copy()
            headers['Content-Type'] = "application/x-www-form-urlencoded"
            headers['Referer'] = MOPAR_BASE_URL
            headers['Sec-Fetch-Site'] = "cross-site"
            res1 = mopar_session.post(SSO_URL, data=payload, headers=headers, allow_redirects=True)  # Allow redirects
            res1.raise_for_status()
            _LOGGER.debug(f"Step 1 - SSO response (first 1000 chars): {res1.text[:1000]}...")
            update_cookies(res1)

            # Check if we’ve been redirected to Mopar or need further action
            if res1.url.startswith(MOPAR_BASE_URL):
                _LOGGER.debug(f"Step 1 - Redirected directly to Mopar: {res1.url}")
            else:
                soup = BeautifulSoup(res1.text, 'html.parser')
                relay_state = soup.find('input', {'name': 'RelayState'})
                saml_response = soup.find('input', {'name': 'SAMLResponse'})
                
                if relay_state and saml_response:
                    relay_state_value = relay_state.get('value')
                    saml_response_value = saml_response.get('value')
                    
                    # Step 2: Post SAML to sign-in URL
                    payload2 = {
                        'RelayState': relay_state_value,
                        'SAMLResponse': saml_response_value
                    }
                    headers['Referer'] = res1.url
                    headers['Sec-Fetch-Site'] = "same-origin"
                    res2 = mopar_session.post(SIGNIN_URL, data=payload2, headers=headers, allow_redirects=True)
                    res2.raise_for_status()
                    _LOGGER.debug(f"Step 2 - Sign-in response: Status {res2.status_code}, URL: {res2.url}, Headers: {res2.headers}, Body (first 1000 chars): {res2.text[:1000]}...")
                    if res2.status_code == 302:
                        _LOGGER.debug(f"Step 2 - Redirected to: {res2.headers.get('location')}")
                    update_cookies(res2)
                else:
                    _LOGGER.warning("No SAML form found—proceeding with cookies to sign-in")
                    # Step 2: Attempt direct sign-in with cookies
                    headers['Referer'] = res1.url
                    res2 = mopar_session.get(SIGNIN_URL, headers=headers, allow_redirects=True)
                    res2.raise_for_status()
                    _LOGGER.debug(f"Step 2 - Direct sign-in response (first 1000 chars): {res2.text[:1000]}...")
                    update_cookies(res2)
                    if res2.status_code == 302 and 'dashboard' in res2.url:
                        _LOGGER.debug(f"Step 2 - Successfully redirected to dashboard: {res2.url}")
                    else:
                        raise MoparError("Failed to authenticate—unexpected response after redirects")

            # Step 3: Verify session with dashboard and refresh for API readiness
            headers['Referer'] = SIGNIN_URL
            res3 = mopar_session.get(DASHBOARD_URL, headers=headers, allow_redirects=True)
            res3.raise_for_status()
            _LOGGER.debug(f"Step 3 - Dashboard response (first 1000 chars): {res3.text[:1000]}...")
            update_cookies(res3)

            # Additional dashboard fetch to ensure full session initialization
            time.sleep(1)  # Small delay to allow server state update
            res4 = mopar_session.get(DASHBOARD_URL, headers=headers, allow_redirects=True)
            res4.raise_for_status()
            _LOGGER.debug(f"Step 4 - Additional dashboard response (first 1000 chars): {res4.text[:1000]}...")
            update_cookies(res4)

            _LOGGER.info("SAML login successful")
            return True
        except requests.exceptions.RequestException as e:
            _LOGGER.error(f"Login failed (attempt {attempt}): {str(e)}")
            if attempt < max_attempts:
                attempt += 1
                continue  # Prompt for new credentials in the next iteration
            return False

async def sign_out() -> str:
    try:
        # Fix the URL by using MOPAR_BASE_URL
        sign_out_url = urljoin(MOPAR_BASE_URL, "sign-out")
        headers = mopar_session.headers.copy()
        res = mopar_session.post(sign_out_url, headers=headers)
        res.raise_for_status()
        mopar_session.cookies.clear()
        return ""
    except requests.exceptions.RequestException as e:
        return str(e) if isinstance(e, requests.exceptions.RequestException) else "An unexpected error occurred"

async def get_user_data() -> Union[Dict, str]:
    try:
        # Fetch the dashboard page after login (already done in sign_in, but we can re-fetch for consistency)
        headers = mopar_session.headers.copy()
        headers.update({
            'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            'Sec-Fetch-Dest': "document",
            'Sec-Fetch-Mode': "navigate",
            'Sec-Fetch-Site': "same-origin",
            'DNT': "1",
            'Sec-GPC': "1"
        })
        _LOGGER.debug(f"Sending GET to {DASHBOARD_URL}")
        _LOGGER.debug(f"Headers: {headers}")
        _LOGGER.debug(f"Cookies: {mopar_session.cookies.get_dict()}")
        res = mopar_session.get(DASHBOARD_URL, headers=headers, allow_redirects=True)
        res.raise_for_status()
        _LOGGER.debug(f"Dashboard response (first 1000 chars): {res.text[:1000]}...")

        # Parse the dashboard HTML to extract user data
        soup = BeautifulSoup(res.text, 'html.parser')
        
        # Example: Extract user profile data (you’ll need to adjust based on actual HTML structure)
        user_data = {}
        
        # Try to find user name (example, adjust selectors based on dashboard HTML)
        user_name_element = soup.find('span', class_='user-name') or soup.find('div', id='user-profile-name')
        if user_name_element:
            user_data['name'] = user_name_element.text.strip()
        
        # Try to find email (example, adjust selectors)
        user_email_element = soup.find('span', class_='user-email') or soup.find('div', id='user-profile-email')
        if user_email_element:
            user_data['email'] = user_email_element.text.strip()
        
        # Try to find other profile info (e.g., account ID, etc.)
        user_id_element = soup.find('span', class_='user-id') or soup.find('div', id='user-profile-id')
        if user_id_element:
            user_data['id'] = user_id_element.text.strip()

        if not user_data:
            raise MoparError("No user data found in dashboard HTML")

        _LOGGER.debug(f"Extracted user data: {json.dumps(user_data, indent=2)}")
        return user_data
    except requests.exceptions.RequestException as e:
        return str(e) if isinstance(e, requests.exceptions.RequestException) else "An unexpected error occurred"
    except Exception as e:
        return str(e)

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
        _LOGGER.debug(f"Sending first GET to {GET_VEHICLES_URL}")
        _LOGGER.debug(f"Headers: {headers}")
        _LOGGER.debug(f"Cookies: {mopar_session.cookies.get_dict()}")
        res1 = mopar_session.get(GET_VEHICLES_URL, headers=headers)
        res1.raise_for_status()
        data1 = res1.json()
        _LOGGER.debug(f"First vehicles response: {json.dumps(data1, indent=2)}")

        # If empty, log a warning and attempt to parse vehicles from dashboard HTML as a fallback
        if not data1 or data1 == []:
            _LOGGER.warning("Vehicle API returned empty list, attempting to parse from dashboard HTML...")
            
            # Fetch and parse dashboard HTML for vehicle data
            dashboard_headers = mopar_session.headers.copy()
            dashboard_headers.update({
                'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                'Sec-Fetch-Dest': "document",
                'Sec-Fetch-Mode': "navigate",
                'Sec-Fetch-Site': "same-origin",
                'DNT': "1",
                'Sec-GPC': "1"
            })
            _LOGGER.debug(f"Sending GET to {DASHBOARD_URL} for vehicle data")
            _LOGGER.debug(f"Headers: {dashboard_headers}")
            _LOGGER.debug(f"Cookies: {mopar_session.cookies.get_dict()}")
            dashboard_res = mopar_session.get(DASHBOARD_URL, headers=dashboard_headers, allow_redirects=True)
            dashboard_res.raise_for_status()
            _LOGGER.debug(f"Dashboard response (first 1000 chars): {dashboard_res.text[:1000]}...")

            # Parse dashboard HTML for vehicle data (adjust selectors based on HTML structure)
            soup = BeautifulSoup(dashboard_res.text, 'html.parser')
            vehicles = []
            
            # Example: Look for vehicle elements (adjust based on dashboard HTML)
            vehicle_elements = soup.find_all('div', class_='vehicle-item') or soup.find_all('li', class_='vehicle-list-item')
            for element in vehicle_elements:
                vehicle = {}
                vin_element = element.find('span', class_='vehicle-vin') or element.find('div', id='vehicle-vin')
                if vin_element:
                    vehicle['vin'] = vin_element.text.strip()
                make_model_element = element.find('span', class_='vehicle-make-model') or element.find('div', id='vehicle-make-model')
                if make_model_element:
                    vehicle['make_model'] = make_model_element.text.strip()
                if vehicle:
                    vehicles.append(vehicle)

            if not vehicles:
                raise MoparError("No vehicle data found in dashboard HTML or API")
            _LOGGER.debug(f"Extracted vehicles from dashboard: {json.dumps(vehicles, indent=2)}")
            return vehicles

        # If 403, retry after a short delay
        if 'errorCode' in data1 and data1['errorCode'] == '403':
            _LOGGER.warning("First getVehicles call returned 403, retrying...")
            time.sleep(2)  # Increased delay to allow server state update
            _LOGGER.debug(f"Sending second GET to {GET_VEHICLES_URL}")
            _LOGGER.debug(f"Headers: {headers}")
            _LOGGER.debug(f"Cookies: {mopar_session.cookies.get_dict()}")
            res2 = mopar_session.get(GET_VEHICLES_URL, headers=headers)
            res2.raise_for_status()
            data2 = res2.json()
            _LOGGER.debug(f"Second vehicles response: {json.dumps(data2, indent=2)}")
            update_cookies(res2)
            return data2
        else:
            update_cookies(res1)
            return data1
    except requests.exceptions.RequestException as e:
        return str(e) if isinstance(e, requests.exceptions.RequestException) else "An unexpected error occurred"

async def get_vehicle_health_report(vin: str) -> Union[Dict, str]:
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
        params = {'vin': vin}
        url = urljoin(mopar_session.base_url, "getVHR")
        _LOGGER.debug(f"Sending GET to {url}")
        _LOGGER.debug(f"Headers: {headers}")
        _LOGGER.debug(f"Params: {params}")
        _LOGGER.debug(f"Cookies: {mopar_session.cookies.get_dict()}")
        res = mopar_session.get(url, headers=headers, params=params)
        res.raise_for_status()
        data = res.json()
        update_cookies(res)
        return data
    except requests.exceptions.RequestException as e:
        return str(e) if isinstance(e, requests.exceptions.RequestException) else "An unexpected error occurred"

async def get_token() -> str:
    try:
        headers = mopar_session.headers.copy()
        headers.update({
            'Accept': "*/*",
            'Sec-Fetch-Dest': "empty",
            'Sec-Fetch-Mode': "cors",
            'Sec-Fetch-Site': "same-origin",
            'DNT': "1",
            'Sec-GPC': "1"
        })
        _LOGGER.debug(f"Sending GET to {MOPAR_BASE_URL}/moparsvc/token")
        _LOGGER.debug(f"Headers: {headers}")
        _LOGGER.debug(f"Cookies: {mopar_session.cookies.get_dict()}")
        res = mopar_session.get(MOPAR_BASE_URL + "/moparsvc/token", headers=headers)
        res.raise_for_status()
        data = res.json()
        update_cookies(res)
        return data['token']
    except requests.exceptions.RequestException as e:
        return str(e) if isinstance(e, requests.exceptions.RequestException) else "An unexpected error occurred"

async def main():
    try:
        # Sign in
        if await sign_in():
            _LOGGER.info("Successfully signed in")

            # Get user data from dashboard HTML
            user_data = await get_user_data()
            if isinstance(user_data, str):
                _LOGGER.error(f"Failed to get user data: {user_data}")
            else:
                _LOGGER.info(f"User data: {json.dumps(user_data, indent=2)}")

            # Get vehicle data
            vehicle_data = await get_vehicle_data()
            if isinstance(vehicle_data, str):
                _LOGGER.error(f"Failed to get vehicle data: {vehicle_data}")
            else:
                _LOGGER.info(f"Vehicle data: {json.dumps(vehicle_data, indent=2)}")

            # Example: Get health report for a vehicle (using VIN from vehicle data if available)
            if isinstance(vehicle_data, list) and vehicle_data:
                vin = vehicle_data[0]['vin']  # Use the first vehicle's VIN
                health_report = await get_vehicle_health_report(vin)
                if isinstance(health_report, str):
                    _LOGGER.error(f"Failed to get health report: {health_report}")
                else:
                    _LOGGER.info(f"Vehicle health report for VIN {vin}: {json.dumps(health_report, indent=2)}")

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