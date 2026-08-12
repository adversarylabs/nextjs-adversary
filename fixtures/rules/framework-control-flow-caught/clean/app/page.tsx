import * as navigation from "next/navigation";

export default async function Page() {
  try {
    const post = await Promise.resolve(null);
    if (!post) navigation.notFound();
    return <main>{post}</main>;
  } catch (error) {
    navigation.unstable_rethrow(error);
    console.error(error);
    return null;
  }
}
