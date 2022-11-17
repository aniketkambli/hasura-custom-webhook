const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const getUuid = require('uuid-by-string');
const fetchData = require('./fetchData');
const getJwkByKid = async (url, kid) => {
    let issResponse;
    issResponse = await fetchData(url);
    for (let index = 0; index < issResponse.keys.length; index++) {
        const key = issResponse.keys[index];
        if (key.kid === kid) {
            return key;
        }
    }
    throw new Error('Failed to find JWK by token KID');
};
module.exports = async (token) => {
    try {
        if (token.search("xoxp") >= 0) {
            let userInfo = await fetchData('https://slack.com/api/users.identity', token);
            const uuidHash = getUuid(userInfo.user?.id);
            const responseObject = {
                payload: {
                    sub: uuidHash,
                }
            };
            return responseObject;
        } else {
            const decodedToken = jwt.decode(token, {
                complete: true
            });
            if (!decodedToken) {
                return 'Unable to verify jwt';
            }
            if (decodedToken.payload.iss === "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_X9bEPtHnF") {
                jwt.verify(token, jwkToPem(await getJwkByKid("https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_X9bEPtHnF/.well-known/jwks.json", decodedToken.header.kid)));
                return decodedToken;
            }
            if (decodedToken.payload.iss.search(/login.microsoftonline.com/) || decodedToken.payload.iss.search(/sts.windows.net/)) {
                jwt.verify(token, jwkToPem(await getJwkByKid("https://login.windows.net/common/discovery/keys", decodedToken.header.kid)));
                const responseObject = {
                    payload: {
                        sub: decodedToken.payload.oid,
                    }
                };
                return responseObject;
            }
        }
    } catch (e) {
        return 'Unable to verify jwt';
    }

}