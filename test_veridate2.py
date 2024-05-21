# https://www.voitanos.io/blog/validating-entra-id-generated-oauth-tokens/
# https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#validate-the-signature

import jwt
from jwt import exceptions
import json
import base64
import requests


TENANT_ID = 'aaaaa-aaaa-aaaaa'
CLIENT_ID = 'bbbbb-bbbb-bbbbb'

def Validate_access_token(access_token):
    j = access_token.split(".")
    header = json.loads(base64.b64decode(j[0]).decode("utf-8"))
    payload = json.loads(base64.b64decode(j[1]).decode("utf-8"))
    signature = j[2]
    url = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0/.well-known/openid-configuration"
    response = requests.get(url).json()
    # #check issuer
    # if response["issuer"] != payload['iss']:
    #     print("Invalid issuer")

    #get public key
    url = response["jwks_uri"]
    response = requests.get(url).json()
    public_key = ""
    for key in response["keys"]:
        if key["x5t"] == header["kid"] and key["kid"] == header["kid"]:
            public_key = key["x5c"][0]
            break

    # verify access_token
    try:
        pem_public_key = f'''-----BEGIN CERTIFICATE-----\n{public_key}\n-----END CERTIFICATE-----'''
        decoded = jwt.decode(access_token, pem_public_key, algorithms=["RS256"])
        print(decoded)
    except exceptions.ExpiredSignatureError:
        print("Token has expired")
    except exceptions.InvalidTokenError as e:
        print(f"Invalid token: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")


access_token = "eyJ0eXAiOiJKV1QiLCJub25jZSI6IlBNZjFHaWlvOGx6OHFsTktxbzlWYjhiMHNOUGEza0ZOeWw1STJEamhGMnMiLCJhbGciOiJSUzI1NiIsIng1dCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCIsImtpZCI6IkwxS2ZLRklfam5YYndXYzIyeFp4dzFzVUhIMCJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9jOTdkMzc5Yy1iMzA1LTQ1YjktYWE2Yi1hMWE4NWQ2ODQwZTcvIiwiaWF0IjoxNzE2MjEzODg4LCJuYmYiOjE3MTYyMTM4ODgsImV4cCI6MTcxNjIxOTU4NiwiYWNjdCI6MCwiYWNyIjoiMSIsImFpbyI6IkFWUUFxLzhXQUFBQTFYM0t0eUVCZExrNElEbnBSbXpad1pjVWw1b1NpU3BYSjdpU3lBeGM5d2JsT1NmaC9JeGpwM1pra2hUVGNhZWdLN3dua2FTTEpjaXZpYVFQTTFNTHF1a3pYcUtZNzFIQVduYkczV2hhcXR3PSIsImFtciI6WyJwd2QiLCJtZmEiXSwiYXBwX2Rpc3BsYXluYW1lIjoiRW50ZXJ0YWlubWVudCBSZWdpc3RyYXRpb24iLCJhcHBpZCI6ImRkMGMxOTJhLWNiMGUtNDM2Ni04OGUwLWFjMzM4NDAyMDE5ZSIsImFwcGlkYWNyIjoiMCIsImZhbWlseV9uYW1lIjoiTmFjd2lqaXQiLCJnaXZlbl9uYW1lIjoiU2FyYXd1dCIsImlkdHlwIjoidXNlciIsImlwYWRkciI6IjE4NC4yMi4yMzEuMTAyIiwibmFtZSI6IlNhcmF3dXQgTmFjd2lqaXQiLCJvaWQiOiJkNmU4ZWMwZS02YWYxLTRiMDgtYTIyZi01NjU5MDgyNmUwNzQiLCJvbnByZW1fc2lkIjoiUy0xLTUtMjEtMTY2MDk5MTk3My0xOTAzNjM4NzkwLTM0NzMwMDI2OTUtMzg5ODEiLCJwbGF0ZiI6IjUiLCJwdWlkIjoiMTAwMzIwMDJGODlBNTk1QSIsInJoIjoiMC5BWElBbkRkOXlRV3p1VVdxYTZHb1hXaEE1d01BQUFBQUFBQUF3QUFBQUFBQUFBRERBTk0uIiwic2NwIjoiVXNlci5SZWFkIHByb2ZpbGUgb3BlbmlkIGVtYWlsIiwic3ViIjoiT0U3TU5ySnFSTmVueVJvNU9fdXNuSERtOC16Q1NhcUNqbmRlM3NmVENBTSIsInRlbmFudF9yZWdpb25fc2NvcGUiOiJBUyIsInRpZCI6ImM5N2QzNzljLWIzMDUtNDViOS1hYTZiLWExYTg1ZDY4NDBlNyIsInVuaXF1ZV9uYW1lIjoic2FyYXd1dF9uYUBkdGdvLmNvbSIsInVwbiI6InNhcmF3dXRfbmFAZHRnby5jb20iLCJ1dGkiOiJtQ0gzNUp1M0RrZURKZHNsZGNxcUFBIiwidmVyIjoiMS4wIiwid2lkcyI6WyJiNzlmYmY0ZC0zZWY5LTQ2ODktODE0My03NmIxOTRlODU1MDkiXSwieG1zX3N0Ijp7InN1YiI6InN4eTJjaGloazNPUEd4dGNQbk1iMmxjSlpfVGJ2Rk5MdXQ2Zy1zMnJhTEEifSwieG1zX3RjZHQiOjE0MzY4NjI1MjR9.JzE5fRsPJWVMKLrZMfgJu-CjGjQEJBqjRjJ6fuWKOT3CeYacO2860EFnY7nQ36lLHCk8L0HeenFIxfgBiUWPhQ5DGjgyo_HI0WmDc18mQgy7cFDkoS2-BOYdj512xltJZ7u2rHuEoN4cDnsIe0OZxCBN1-GjW5HDK_79y3PYJ6qpPKiv8YdiAuEEUw1sjsZg9sK12flImFzNHj5iC9nAXC0SCetVRyi5tYcGJ4tmRtldcjPgVG6FWJMu8U-Cx1Q4fKXgkujhiLBY12uT6Ge3OfRRW1F0qBc9fFZod4EwfoSekcAFt_v0nhpqubH1ukci2EsEVa6vcOEzk6SMWNHmxQ"
Validate_access_token(access_token)


