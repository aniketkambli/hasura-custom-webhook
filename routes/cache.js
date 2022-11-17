var mcache = require("memory-cache");
const jwt = require("jsonwebtoken");
module.exports = (duration) => {
  let cacheKey = "";
  return (req, res, next) => {
    if (!req.get("Authorization")) {
      next();
      return;
    }
    var token = req.get("Authorization").split(" ")[1];
    let cachedBody = "";
    if (token.search("xoxp") >= 0) {
      cacheKey = token;
      cachedBody = mcache.get(token);
    } else {
      const decodedToken = jwt.decode(token, {
        complete: true,
      });
      if (
        decodedToken.payload.iss ===
        "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_X9bEPtHnF"
      ) {
        cacheKey = decodedToken.payload.sub;
        cachedBody = mcache.get(decodedToken.payload.sub);
      }
      if (
        decodedToken.payload.iss.search(/login.microsoftonline.com/) ||
        decodedToken.payload.iss.search(/sts.windows.net/)
      ) {
        cacheKey = decodedToken.payload.oid;
        cachedBody = mcache.get(decodedToken.payload.oid);
      }
    }
    if (cachedBody) {
      res.send(cachedBody);
      return;
    } else {
      res.sendResponse = res.send;
      res.send = (body) => {
        if (body !== `{"msg":"Unable to verify"}`) {
          mcache.put(cacheKey, body, duration * 1000);
        }
        res.sendResponse(body);
        return;
      };
      next();
    }
  };
};
