import { notFound } from "next/navigation";
import { CAPABILITIES, capabilityBySlug, titleOf } from "@/lib/visitor/capabilities";
import { CapabilityDetail } from "./capability-detail";

export const dynamicParams = false;

export function generateStaticParams() {
  return CAPABILITIES.map((c) => ({ slug: c.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const cap = capabilityBySlug(slug);
  return { title: cap ? `${titleOf(cap.id)} — RASHIELD` : "RASHIELD" };
}

export default async function CapabilityPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  if (!capabilityBySlug(slug)) notFound();
  return <CapabilityDetail slug={slug} />;
}
