"use server";

import { redirect, unstable_rethrow as preserveFrameworkError } from "next/navigation";

export async function createPost() {
  try {
    await Promise.resolve();
  } catch (error) {
    return { error: "Could not create post" };
  }
  redirect("/posts");
}

export async function updatePost() {
  try {
    await Promise.resolve();
    redirect("/posts");
  } catch (error) {
    preserveFrameworkError(error);
    return { error: "Could not update post" };
  }
}

export async function deletePost() {
  try {
    await Promise.resolve();
    redirect("/posts");
  } catch (error) {
    throw error;
  }
}

export function unrelatedLocalHelper() {
  function redirect(path: string) {
    return path;
  }
  try {
    return redirect("/local");
  } catch {
    return "/";
  }
}

export function delayedRedirect() {
  try {
    return () => redirect("/later");
  } catch {
    return () => undefined;
  }
}
