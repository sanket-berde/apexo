import { text } from "@core";
import {
	CaseJSON,
	EndoCaseJSON,
	CephalometricItem,
	genderToString,
	patients,
	PhotoJSON,
	Photo,
	Visit,
	setting,
	VisitJSON
	} from "@modules";
import { formatDate, generateID } from "@utils";
import { computed, observable, observe } from "mobx";

export const Access = {
	done: "Done",
	notdone: "Not done"
};

export const Cleaning = {
	done: "Done",
	notdone: "Not done"
};

export const Obturation = {
	done: "Done",
	notdone: "Not done"
};



export class EndoCase {
	_id: string = generateID();
	@observable triggerUpdate: number = 0;
	@observable startedDate: number = 0;

	@observable patientID: string = "";
	@computed
	get patient() {
		return patients.list.find(x => x._id === this.patientID);
	}

	/**
	 * Extra-oral observations
	 */
	@observable access: keyof typeof Access = "notdone";
	@observable cleaning: keyof typeof Cleaning = "notdone";
	@observable obturation: keyof typeof Obturation = "notdone";
	

	/**
	 * inputs
	 */
	@observable workinglength: number = 0; //In mm
	@observable canals: number = 1; //whole numbers

	

	/**
	 * conclusions
	 */
	@observable problemsList: string[] = [];
	@observable treatmentPlan_appliance: string[] = [];

	@observable orthoGallery: string[] = [];

	@observable cephalometricHistory: CephalometricItem[] = [];

	@observable isFinished: boolean = false;
	@observable isStarted: boolean = false;
	@observable finishedDate: number = 0;

	@observable nextVisitNotes: string[] = [];

	@observable visits: Visit[] = [];

	@computed
	get computedProblems() {
		const computedProblemsArr: string[] = [];
		if (this.access !== "done") {
			computedProblemsArr.push(text(Access[this.access]));
		}

		if (this.cleaning !== "done") {
			computedProblemsArr.push(text(Cleaning[this.cleaning]));
		}

		if (this.obturation === "done") {
			computedProblemsArr.push(text(Obturation[this.obturation]));
		}

		

		return computedProblemsArr;
	}

	@computed
	get searchableString() {
		return !this.patient
			? ""
			: `
			${this.patient.age} ${this.patient.birthYear}
			${this.patient.phone} ${this.patient.email} ${
					this.patient.address
			  } ${genderToString(this.patient.gender)}
			${this.patient.name} ${this.patient.labels
					.map(x => x.text)
					.join(" ")} ${this.patient.medicalHistory.join(" ")}
			${this.patient.teeth.map(x => x.notes.join(" ")).join(" ")}
			${
				this.patient.nextAppointment
					? (this.patient.nextAppointment.treatment || { type: "" })
							.type
					: ""
			}
			${
				this.patient.nextAppointment
					? formatDate(
							this.patient.nextAppointment.date,
							setting.getSetting("date_format")
					  )
					: ""
			}
			${
				this.patient.lastAppointment
					? (this.patient.lastAppointment.treatment || { type: "" })
							.type
					: ""
			}
			${
				this.patient.lastAppointment
					? formatDate(
							this.patient.lastAppointment.date,
							setting.getSetting("date_format")
					  )
					: ""
			}
			${
				this.patient.differenceAmount < 0
					? "outstanding " + this.patient.outstandingAmount
					: ""
			}
			${
				this.patient.differenceAmount > 0
					? "Overpaid " + this.patient.overpaidAmount
					: ""
			}
		`.toLowerCase();
	}

	constructor(json?: EndoCaseJSON) {
		if (json) {
			this.fromJSON(json);
		} else {
			//observe(this.crossScissorBite, () => this.triggerUpdate++);
			observe(this.problemsList, () => this.triggerUpdate++);
			observe(this.treatmentPlan_appliance, () => this.triggerUpdate++);
			observe(this.orthoGallery, () => this.triggerUpdate++);
			observe(this.cephalometricHistory, () => this.triggerUpdate++);
			observe(this.visits, () => {
				this.triggerUpdate++;
			});
		}
	}

	toJSON(): EndoCaseJSON {
		return {
			_id: this._id,
			patientID: this.patientID,
			startedDate: this.startedDate,
			isStarted: this.isStarted,
			
			access: this.access,
			cleaning: this.cleaning,
			obturation: this.obturation,	
			workinglength:  this.workinglength,
			canals:  this.canals,

			problemsList: Array.from(this.problemsList),			
			treatmentPlan_appliance: Array.from(this.treatmentPlan_appliance),
			orthoGallery: Array.from(this.orthoGallery),
			cephalometricHistory: Array.from(this.cephalometricHistory),
			isFinished: this.isFinished,
			finishedDate: this.finishedDate,
			nextVisitNotes: Array.from(this.nextVisitNotes),
			visits: Array.from(this.visits).map(x => x.toJSON())
		};
	}

	fromJSON(json: EndoCaseJSON) {
		this._id = json._id;
		this.startedDate = json.startedDate || 0;
		this.patientID = json.patientID;

		this.access = json.access,
		this.cleaning = json.cleaning,
		this.obturation = json.obturation,
		this.workinglength = json.workinglength,
		this.canals = json.canals,		
		
		this.cephalometricHistory = json.cephalometricHistory || [];
		this.isFinished = !!json.isFinished;
		this.finishedDate = json.finishedDate || 0;
		this.nextVisitNotes = json.nextVisitNotes || [];
		this.visits = json.visits ? json.visits.map(x => new Visit(x)) : [];
		this.isFinished = !!json.isFinished;
		this.isStarted = !!json.isStarted;
		
		observe(this.problemsList, () => this.triggerUpdate++);
		observe(this.treatmentPlan_appliance, () => this.triggerUpdate++);
		observe(this.orthoGallery, () => this.triggerUpdate++);
		observe(this.cephalometricHistory, () => this.triggerUpdate++);
		observe(this.visits, () => {
			this.triggerUpdate++;
		});
	}
}
