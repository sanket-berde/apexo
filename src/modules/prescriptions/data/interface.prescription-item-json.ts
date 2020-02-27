export interface PrescriptionItemJSON {
	_id: string;
	name: string;
	doseInMg: number;
	timesPerDay: number;
	form: string;
	unitsPerTime: number;
	notes: string; // Added on October 2019
}
