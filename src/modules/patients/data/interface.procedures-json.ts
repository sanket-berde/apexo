export interface ProceduresJSON {
  id: string;
  slectedGraphicCode: string[];
  patientid: string;
  name: string;
  done: boolean;
  date: string;
  tooth: number[];
  fees: number;
  quantity: number;
  // priority: number;
  // desc?: string;
  // discount?: string;
  // fdiscount?: string;
  // insurance?: string;
  // psignature?: string;
}
