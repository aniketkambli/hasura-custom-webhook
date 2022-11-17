const fetch = require("node-fetch");
module.exports= async (endpoint, token) => {
    const headers = token ? {
        Authorization: `Bearer ${token}`,
    } : null;
    const data = await fetch(
        endpoint, {
            method: "GET",
            headers: headers ? headers : null
        }
    );
    let response = await data.json();
    return response;
};