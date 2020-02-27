import { Access, Cleaning, Obturation, VisitJSON, CephalometricItem } from "@modules";


export interface EndoCaseJSON {
	_id: string;
	patientID: string;
	
	access: keyof typeof Access;
	cleaning: keyof typeof Cleaning;	
	obturation: keyof typeof Obturation;	
	workinglength:  number;
	canals:  number;
	
	problemsList: string[];
	treatmentPlan_appliance: string[];
	orthoGallery: string[];
	cephalometricHistory: CephalometricItem[];
	isFinished: boolean;
	isStarted: boolean;
	startedDate: number;
	finishedDate: number;
	nextVisitNotes: string[];
	visits: VisitJSON[];
}