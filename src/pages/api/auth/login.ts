import type { NextApiRequest, NextApiResponse } from "next";
import { login_handler } from "../../../server/handlers/auth_handlers";

export default (req: NextApiRequest, res: NextApiResponse) => {
  if (req.method === "POST") {
    return post_handler(req, res);
  }

  return res.status(405).json({ error: "Method not allowed" });
};

const post_handler = async (req: NextApiRequest, res: NextApiResponse) => {
  // validate the request body first
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Missing email or password" });
  }

  try {
    // create user
    const user = await login_handler(email, password);

    return res
      .setHeader("Authorization", `Bearer ${user.session_token}`)
      .status(200)
      .json(user);
  } catch (err) {
    return res.status(401).json({ error: err });
  }
};
