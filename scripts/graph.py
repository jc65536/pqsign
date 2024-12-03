from matplotlib.gridspec import GridSpec
import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
from matplotlib.colors import LinearSegmentedColormap
from numpy.typing import NDArray

buf_size = np.arange(100, 2100, 100)
delay = np.arange(0, 200, 10)

delay, buf_size = np.meshgrid(delay, buf_size)

time_plain = np.load(f"../out/plain-tls.npy")
time_pqc = np.load(f"../out/pqc-tls.npy")
time_caching = np.load(f"../out/pqc-with-caching.npy")

tmax = max(time_plain.max(), time_pqc.max(), time_caching.max())

fig = plt.figure(figsize=(6, 14))
gs = GridSpec(1, 4, width_ratios=(1, 1, 1, 0.1))

cmap = LinearSegmentedColormap.from_list("my_cmap", (
    (0, "#ff00ff"),
    (0.05, "#0000ff"),
    (0.1, "#00ff00"),
    (0.2, "#ffff00"),
    (1, "#ff0000"),
))


def make_fig(cell: tuple[int, int], data: NDArray, title: str):
    ax: Axes3D = fig.add_subplot(gs[cell], projection="3d")

    surf = ax.plot_surface(delay, buf_size, data,
                           cmap=cmap, vmin=0, vmax=tmax)

    ax.set_xlabel("Latency (ms)")
    ax.set_ylabel("Bandwidth (bytes)")
    ax.set_zlabel("Handshake time (ms)")
    ax.set_zlim3d(0, 10000)
    ax.view_init(azim=135)
    ax.set_title(title)

    return surf


make_fig((0, 0), time_plain, "Classical algorithm")
make_fig((0, 1), time_pqc, "Post-quantum algorithm")
surf = make_fig((0, 2), time_caching, "Post-quantum algorithm and caching")

cax = fig.add_subplot(gs[0, 3])
fig.colorbar(surf, cax=cax)

gs.tight_layout(fig, w_pad=8)

plt.show()
fig.savefig("../out/combined.png", transparent=True)
