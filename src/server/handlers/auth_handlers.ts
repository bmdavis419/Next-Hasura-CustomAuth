import { prisma } from "../common/db";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { env } from "../../env/server.mjs";

const create_token = async (id: number) => {
  // ensure that the user exists
  const user = await prisma.user.findUnique({
    where: {
      id: id,
    },
  });
  if (!user) {
    throw new Error("User not found");
  }

  // setup the token
  const token_contents = {
    sub: user.id,
    name: user.first_name + " " + user.last_name,
    email: user.email,
    iat: Date.now() / 1000,
    "https://hasura.io/jwt/claims": {
      "x-hasura-allowed-roles": ["user"],
      "x-hasura-default-role": "user",
      "x-hasura-user-id": user.id.toString(),
    },
    exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
  };

  const token = jwt.sign(token_contents, env.JWT_SECRET);

  const loggedInUser = await prisma.user.update({
    data: { session_token: { set: token } },
    where: { id: user.id },
  });

  return loggedInUser;
};

export const login_handler = async (email: string, password: string) => {
  // check if user exists
  const existing_user = await prisma.user.findUnique({
    where: {
      email: email,
    },
  });
  if (!existing_user) {
    throw new Error("User does not exist!");
  }

  // check if password is correct
  const password_matches =
    existing_user.password &&
    bcrypt.compareSync(password, existing_user.password);
  if (!password_matches) {
    throw new Error("Incorrect password!");
  }

  // return user
  const user = await create_token(existing_user.id);
  return user;
};

export const delete_user_handler = async (id: number) => {
  try {
    const user = await prisma.user.update({
      data: { deleted_at: { set: new Date() } },
      where: { id },
    });
    return user;
  } catch (err) {
    throw new Error("Error while deleting user");
  }
};

export const refresh_token_handler = async (token: string) => {
  try {
    // TODO: TYPE THIS
    const decoded = jwt.verify(
      token,
      "YzUfzRU1hkq7DG+wrJoTb6iVdcV+7kLV"
    ) as any;
    const usedId = decoded["https://hasura.io/jwt/claims"]["x-hasura-user-id"];
    const newToken = await create_token(usedId);
    return newToken;
  } catch (err) {
    throw new Error("Error while refreshing token");
  }
};

export const register_handler = async (
  email: string,
  password: string,
  first_name: string,
  last_name: string
) => {
  // check if user exists
  const existing_user = await prisma.user.findFirst({
    where: {
      email: {
        equals: email,
        mode: "insensitive",
      },
    },
  });
  if (existing_user) {
    throw new Error("User already exists!");
  }

  // hash password
  const hashed_password = bcrypt.hashSync(password, 10);

  // create user
  const user = await prisma.user.create({
    data: {
      email,
      password: hashed_password,
      first_name,
      last_name,
    },
  });

  // return user
  return user;
};
