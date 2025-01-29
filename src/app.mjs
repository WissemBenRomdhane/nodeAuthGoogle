import express from "express";
import cookieParser from "cookie-parser";
import { randomBytes } from "crypto";
import { config as configDotenv } from "dotenv";
import session from "express-session";

const app = express();
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: true,
  })
);
configDotenv();

app.get("/authenticate", (request, response) => {
  let url = `https://accounts.google.com/o/oauth2/auth?`;
  url += `&response_type=code`;
  url += `&client_id=${process.env.CLIENT_ID}`;
  url += `&redirect_uri=http://localhost:3000/authorization_callback`;
  url += `&scope=email`;

  const state = randomBytes(4).toString("hex");
  url += `&state=${state}`;

  response.cookie("state", state);
  response.redirect(url);
});

app.get("/authorization_callback", async (request, response) => {
  const authorization_code = request.query["code"];
  const state_from_callback = request.query["state"];
  const state_from_cookie = request.cookies["state"];

  if (state_from_callback != state_from_cookie) {
    response.status(400).send(`Invalid state`);
  }
  let body = `grant_type=authorization_code`;
  body += `&code=${authorization_code}`;
  body += `&redirect_uri=http://localhost:3000/authorization_callback`;
  body += `&client_id=${process.env.CLIENT_ID}`;
  body += `&client_secret=${process.env.CLIENT_SECRET}`;

  let token_response = await fetch(`https://oauth2.googleapis.com/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: body,
  });

  if (!token_response.ok) {
    return response.status(500).send(`Internal server error`);
  }

  const token_response_json = await token_response.json();

  let signed_request_response = await fetch(
    `https://www.googleapis.com/oauth2/v2/userinfo`,
    {
      headers: {
        Authorization: `Bearer ${token_response_json.access_token}`,
      },
    }
  );
  const signed_request_response_json = await signed_request_response.json();

  request.session.user = signed_request_response_json;
  response.status(200).send(signed_request_response_json);
});

app.get("/logout", (request, response) => {
  request.session.destroy((error) => {
    if (error) {
      response.status(500).send(`error destroying session ${error}`);
    } else {
      response.clearCookie("connect.sid", { path: "/" });
      response.status(200).send(`user logged out, session destroyed.`);
    }
  });
});

app.get("/protected", (request, response) => {
  if (!request.session.user) {
    return response.redirect("/authenticate");
  }
  response.status(200).send(`Hello, ${request.session.user.email}`);
});

app.listen(3000, () => {
  console.log(`Server is running on port 3000`);
});
