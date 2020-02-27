import { router } from "@core";
import { computed, observable } from "mobx";

export interface MenuItem {
	name: string;
	key: string;
	url: string;
	icon: string;
	onClick: () => void;
	order: number;
	condition?: () => boolean;
}

class MenuData {
	@observable
	items: MenuItem[] = [
		{
			icon: "Home",
			name: "Home",
			order: -99,
			key: "Home",
			url: "",
			onClick: () => {
				router.go([""]);
			}
		}
	];

	@observable visible: boolean = false;

	@computed
	get sortedItems() {
		const items = this.items
			.slice()
			.reduce((arr: MenuItem[], item) => {
				if (arr.findIndex(x => x.key === item.key) === -1) {
					arr.push(item);
				}
				return arr;
			}, [])
			// .sort((a, b) => a.order - b.order)
			.filter(item => !item.condition || item.condition());

			items.push(
				{
					icon: "message",
					name: "Contact us",
					order: -99,
					key: "contacts",
					url: "",
					onClick: () => {
						var link = document.createElement('a');
						link.href = "mailto:contact@365apex.com";
						document.body.appendChild(link);
						link.click();
					}
				},
				{
					icon: "help",
					name: "Support",
					order: -99,
					key: "support",
					url: "",
					onClick: () => {
						window.location.href = "https://www.365apex.com/support";
					}
				}
			);

			return items;
	}

	@computed
	get currentIndex() {
		return this.sortedItems.findIndex(
			x => x.name === router.currentNamespace
		);
	}

	hide() {
		this.visible = false;
	}

	show() {
		this.visible = true;
	}
}

export const menu = new MenuData();
