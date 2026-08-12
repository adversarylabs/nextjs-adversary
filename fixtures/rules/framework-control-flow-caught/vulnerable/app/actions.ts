"use server";

import { permanentRedirect, redirect as goTo } from "next/navigation";

export async function createPost() {
  try {
    await Promise.resolve();
    goTo("/posts");
  } catch (error) {
    return { error: "Could not create post" };
  }
}

export async function renameProfile() {
  try {
    await Promise.resolve();
    permanentRedirect("/profile/new-name");
  } catch (error) {
    console.error(error);
  }
}
