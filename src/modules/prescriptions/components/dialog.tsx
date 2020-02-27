import { TextField, Dialog, DialogType, DialogFooter, PrimaryButton, DefaultButton } from "office-ui-fabric-react";
import {  PrescriptionItem, prescriptions } from "@modules";
import * as React from "react";

interface MyState {
    hideDialog: boolean;
  }

export default class PrintPrescriptionPage extends React.Component<{ prescription?: string; onDismiss?: () => void; onPrint?: () => void;  show: boolean;  }, MyState> {
    
    render() {

        return (
           <div>
            <Dialog
            hidden={this.props.show}
            onDismiss={this.props.onDismiss}
            dialogContentProps={{
                type: DialogType.largeHeader,
                title: 'Type your Name and Upload an Icon as A Dentist',
                subText: 'Follow instructions'
            }}
            modalProps={{
                isBlocking: false,
                styles: { main: { maxWidth: 450 } }
            }}
            >
                                    <TextField
											label="Dentist's Name: "
											type="text"
											
										/>
                                    <br/>
                                    <TextField
											label="Print Logo: "
											type="file"
											
										/>
            
                <DialogFooter>
                    <PrimaryButton onClick={this.props.onPrint} text="Print" />
                    <DefaultButton onClick={this.props.onDismiss} text="Cancel" />
                </DialogFooter>
            </Dialog>
            </div>
        )
    }

    /*  private _showDialog = (): void => {
        this.setState({ hideDialog: false });
      };
    
      private _closeDialog = (): void => {
        this.setState({ hideDialog: true });
      };*/
}