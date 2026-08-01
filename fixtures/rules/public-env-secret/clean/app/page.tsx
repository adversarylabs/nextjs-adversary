export default function Page() {
  const key = process.env.NEXT_PUBLIC_ANALYTICS_ID;
  return <div>{key}</div>;
}
