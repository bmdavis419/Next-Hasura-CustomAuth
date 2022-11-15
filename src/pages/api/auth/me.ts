import type { NextApiRequest, NextApiResponse } from "next";
import {
  login_handler,
  me_handler,
} from "../../../server/handlers/auth_handlers";

export default (req: NextApiRequest, res: NextApiResponse) => {
  if (req.method === "POST") {
    return post_handler(req, res);
  }

  return res.status(405).json({ error: "Method not allowed" });
};

const post_handler = async (req: NextApiRequest, res: NextApiResponse) => {
  try {
    // create user
    const user = await me_handler(req);

    return res
      .setHeader("Authorization", `Bearer ${user.session_token}`)
      .status(200)
      .json(user);
  } catch (err) {
    return res.status(401).json({ error: err });
  }
};
