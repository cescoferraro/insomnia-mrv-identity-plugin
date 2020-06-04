const axios = require("axios");
const jwt = require("njwt");
const qs = require("querystring");

let global_token = null;
let global_expiration = null;

module.exports.templateTags = [
    {
        name: "token",
        displayName: "MRV Identity Token",
        description: "Generate a JWT token from MRV Identity Server",
        args: [
            {displayName: "username", description: "username", type: "string"},
            {displayName: "password", description: "password", type: "string"},
        ],
        run: async (ctx, username, password) => {
            const {context} = ctx;
            if (context.name.includes("local"))
                return jwt.create({preferred_username: username}, "top-secret-phrase");
            try {
                if (global_token != null)
                    if (global_expiration > new Date().getTime())
                        return global_token;
                const config = {headers: {"Content-Type": "application/x-www-form-urlencoded"}};
                const grant_type = "password";
                const {client_id} = context;
                const {client_secret} = context;
                const body = {username, password, grant_type, client_id, client_secret};
                const {data} = await axios.post(context.auth, qs.stringify(body), config);
                global_token = data.access_token;
                global_expiration = new Date().getTime() + data.expires_in;
                return data.access_token;
            } catch (e) {
                return "internal error";
            }
        },
    }
];

