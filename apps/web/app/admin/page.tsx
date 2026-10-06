import { AdminConsole } from "../../components/AdminConsole";

export default async function AdminPage({
  searchParams,
}: {
  searchParams: Promise<{
    organizationId?: string;
  }>;
}) {
  const params = await searchParams;

  return (
    <AdminConsole
      initialOrganizationId={
        params.organizationId ?? ""
      }
    />
  );
}
