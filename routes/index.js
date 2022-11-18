var express = require("express");
var router = express.Router();
const cache = require("./cache");
const verifyToken = require("./verifyToken");
router.get("/", (req, res) => {
  res.send("Welcome to custom webserver");
});
router.get("/webhook", cache(5400), async (request, response) => {
  // Extract token from request
  if (!request.get("Authorization")) {
    return response.status(401).json({
      msg: `No authorization header`,
    });
  }
  var token = request.get("Authorization").split(" ")[1];
  // Fetch user_id that is associated with this token
  const result = await verifyToken(token);
  if (result === "Unable to verify jwt") {
    return response.status(401).json({
      msg: `Unable to verify`,
    });
  } else {
    // Return appropriate response to Hasura
    var hasuraVariables = {
      "x-hasura-role": "user", // result.role
      "x-hasura-user-id": result.payload.sub, // result.user_id
    };
    return response.status(200).json(hasuraVariables);
  }
});

module.exports = router;
