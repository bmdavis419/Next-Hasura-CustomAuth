import type { NextApiRequest, NextApiResponse } from "next";
import {
  register_handler,
  create_token,
} from "../../../server/handlers/auth_handlers";

export default (req: NextApiRequest, res: NextApiResponse) => {
  if (req.method === "POST") {
    return post_handler(req, res);
  }

  return res.status(405).json({ error: "Method not allowed" });
};

const post_handler = async (req: NextApiRequest, res: NextApiResponse) => {
  // validate the request body first
  const { email, password, first_name, last_name } = req.body;
  if (!email || !password || !first_name || !last_name) {
    return res.status(400).json({ error: "Missing email or password" });
  }

  try {
    // create user
    const user = await register_handler(email, password, first_name, last_name);

    // create token
    const { session_token } = await create_token(user.id);

    return res
      .setHeader("Authorization", `Bearer ${session_token}`)
      .status(200)
      .json({ user });
  } catch (err) {
    return res.status(401).json({ error: err });
  }
};
