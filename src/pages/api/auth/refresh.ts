import type { NextApiRequest, NextApiResponse } from "next";
import { refresh_token_handler } from "../../../server/handlers/auth_handlers";

export default (req: NextApiRequest, res: NextApiResponse) => {
  if (req.method === "POST") {
    return post_handler(req, res);
  }

  return res.status(405).json({ error: "Method not allowed" });
};

const post_handler = async (req: NextApiRequest, res: NextApiResponse) => {
  try {
    const token = req?.headers?.authorization
      ? (req?.headers?.authorization as string).split("Bearer ")[1]
      : "";

    if (!token) {
      return res.status(400).json("Error parsing authorization token");
    }

    const user = await refresh_token_handler(token);
    res
      .setHeader("Authorization", `Bearer ${user.session_token}`)
      .json({ token: user.session_token });
  } catch (err) {
    res.status(500).send(err);
  }
};
