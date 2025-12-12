from daedaluslink import DaedalusLink

gui = DaedalusLink(name="R2D2", link_id=12345)

#gui.enable_authentication()
gui.add_user("pilot", "password123", role="user")
gui.add_user("maint", "myadminpwd", role="admin")
gui.add_user("dev", "supersecretdev", role="developer")

gui.add_button("forward", command="MOVE_FORWARD", position=[0, 2], size=[4, 1])
gui.add_button("backward", command="MOVE_BACKWARD", position=[4, 2], size=[4, 1])
gui.add_joystick("move", axes=["X", "Y"], command="move", position=[2, 7], size=[6, 6])
gui.add_slider("Joint 1", command="j1", position=[0, 3], size=[1, 9])
gui.add_slider("Joint 2", command="j2", position=[1, 3], size=[1, 9])

gui.enable_discovery_broadcast(
    udp_port=7777,
    interval=1.0
)

@gui.on("MOVE_FORWARD")
def forward(pressed: bool):
    if pressed:
        print("forward pressed")
    else:
        print("forward released")

@gui.on("MOVE_BACKWARD")
def backward(pressed: bool):
    if pressed:
        print("backward pressed")
    else:
        print("backward released")

@gui.on("move")
def on_move(x: int, y: int):
    print(f"Joystick moved → x={x}, y={y}")

@gui.on("j1")
def sliderj1(x: int):
    print(f"slider j1 moved → {x}")

@gui.on("j2")
def sliderj2(x: int):
    print(f"slider j2 moved → {x}")

gui.run(port=8081)
