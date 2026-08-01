export default function Page() {
  const key = process.env.NEXT_PUBLIC_SERVICE_ROLE_KEY;
  return <div>{key}</div>;
}
