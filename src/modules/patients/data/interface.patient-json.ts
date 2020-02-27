import { ToothJSON } from "@modules";
import { ProceduresJSON } from "@modules";

export interface PatientJSON {
  _id: string;
  name: string;
  birthYear: number;
  gender: string;
  tags: string;
  address: string;
  email: string;
  phone: string;
  medicalHistory: string[];
  procedureGraphicCode: string[];
  gallery: string[];
  teeth: (ToothJSON | null)[];
  procedures: (ProceduresJSON | null)[];
  labels: {
    text: string;
    type: string;
  }[];
}
